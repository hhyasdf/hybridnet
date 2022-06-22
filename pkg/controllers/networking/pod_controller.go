/*
 Copyright 2021 The Hybridnet Authors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package networking

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/controllers/concurrency"
	"github.com/alibaba/hybridnet/pkg/controllers/utils"
	"github.com/alibaba/hybridnet/pkg/ipam/strategy"
	"github.com/alibaba/hybridnet/pkg/ipam/types"
	ipamtypes "github.com/alibaba/hybridnet/pkg/ipam/types"
	"github.com/alibaba/hybridnet/pkg/metrics"
	globalutils "github.com/alibaba/hybridnet/pkg/utils"
	"github.com/alibaba/hybridnet/pkg/utils/transform"
)

const ControllerPod = "Pod"

const (
	ReasonIPAllocationSucceed = "IPAllocationSucceed"
	ReasonIPAllocationFail    = "IPAllocationFail"
	ReasonIPReleaseSucceed    = "IPReleaseSucceed"
	ReasonIPReserveSucceed    = "IPReserveSucceed"
)

const (
	IndexerFieldNode  = "node"
	OverlayNodeName   = "c3e6699d28e7"
	GlobalBGPNodeName = "d7afdca2c149"
)

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	APIReader client.Reader
	client.Client

	Recorder record.EventRecorder

	PodIPCache  PodIPCache
	IPAMStore   IPAMStore
	IPAMManager IPAMManager

	concurrency.ControllerConcurrency
}

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=pods/finalizers,verbs=update

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrllog.FromContext(ctx)

	var (
		pod         = &corev1.Pod{}
		networkName string
	)

	defer func() {
		if err != nil {
			log.Error(err, "reconciliation fails")
			if len(pod.UID) > 0 {
				r.Recorder.Event(pod, corev1.EventTypeWarning, ReasonIPAllocationFail, err.Error())
			}
		}
	}()

	if err = r.Get(ctx, req.NamespacedName, pod); err != nil {
		if err = client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to fetch Pod: %v", err)
		}
		return ctrl.Result{}, nil
	}

	if pod.DeletionTimestamp != nil {
		if strategy.OwnByStatefulWorkload(pod) {
			if err = r.reserve(ctx, pod); err != nil {
				return ctrl.Result{}, wrapError("unable to reserve pod", err)
			}
			return ctrl.Result{}, wrapError("unable to remote finalizer", r.removeFinalizer(ctx, pod))
		}
		return ctrl.Result{}, nil
	}

	// Pre decouple ip instances for completed or evicted pods
	if utils.PodIsEvicted(pod) || utils.PodIsCompleted(pod) {
		return ctrl.Result{}, wrapError("unable to decouple pod", r.decouple(ctx, pod))
	}

	cacheExist, uid, ipInstanceList := r.PodIPCache.Get(pod.Name, pod.Namespace)
	// To avoid IP duplicate allocation
	if cacheExist && uid == pod.UID {
		ipFamily := ipamtypes.ParseIPFamilyFromString(pod.Annotations[constants.AnnotationIPFamily])

		if (len(ipInstanceList) == 1 && (ipFamily == ipamtypes.IPv4 || ipFamily == ipamtypes.IPv6)) ||
			(len(ipInstanceList) == 2 && ipFamily == ipamtypes.DualStack) {
			return ctrl.Result{}, nil
		}

		if len(ipInstanceList) > 0 {
			return ctrl.Result{}, fmt.Errorf("duplicated ip instances exist for pod: %v/%v, pod ip family is %v",
				pod.Namespace, pod.Name, ipFamily)
		}
	}

	networkName, err = r.selectNetwork(ctx, pod)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to select network: %v", err)
	}

	if strategy.OwnByStatefulWorkload(pod) {
		log.V(1).Info("strategic allocation for pod")
		return ctrl.Result{}, wrapError("unable to stateful allocate", r.statefulAllocate(ctx, pod, networkName))
	}

	return ctrl.Result{}, wrapError("unable to allocate", r.allocate(ctx, pod, networkName))
}

// decouple will unbind IP instance with Pod
func (r *PodReconciler) decouple(ctx context.Context, pod *corev1.Pod) (err error) {
	if err = r.IPAMStore.DeCouple(ctx, pod); err != nil {
		return fmt.Errorf("unable to decouple ips for pod %s: %v", client.ObjectKeyFromObject(pod).String(), err)
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, ReasonIPReleaseSucceed, "pre decouple all IPs successfully")
	return nil
}

// reserve will reserve IP instances with Pod
func (r *PodReconciler) reserve(ctx context.Context, pod *corev1.Pod) (err error) {
	if err = r.IPAMStore.IPReserve(ctx, pod); err != nil {
		return fmt.Errorf("unable to reserve ips for pod: %v", err)
	}

	r.Recorder.Event(pod, corev1.EventTypeNormal, ReasonIPReserveSucceed, "reserve all IPs successfully")
	return nil
}

// selectNetwork will pick the hit network by pod, taking the priority as below
// 1. explicitly specify network in pod annotations/labels
// 2. parse network type from pod and select a corresponding network binding on node
func (r *PodReconciler) selectNetwork(ctx context.Context, pod *corev1.Pod) (string, error) {
	var specifiedNetwork string
	if specifiedNetwork = globalutils.PickFirstNonEmptyString(pod.Annotations[constants.AnnotationSpecifiedNetwork], pod.Labels[constants.LabelSpecifiedNetwork]); len(specifiedNetwork) > 0 {
		return specifiedNetwork, nil
	}

	var networkType = types.ParseNetworkTypeFromString(globalutils.PickFirstNonEmptyString(pod.Annotations[constants.AnnotationNetworkType], pod.Labels[constants.LabelNetworkType]))
	switch networkType {
	case types.Underlay:
		// try to get underlay network by node name
		underlayNetworkName, err := r.getNetworkByNodeNameIndexer(ctx, pod.Spec.NodeName)
		if err != nil {
			return "", fmt.Errorf("unable to get underlay network by node name indexer: %v", err)
		}

		if len(underlayNetworkName) == 0 {
			return "", fmt.Errorf("unable to find underlay network for node %s", pod.Spec.NodeName)
		}

		return underlayNetworkName, nil
	case types.Overlay:
		// try to get overlay network by special node name
		overlayNetworkName, err := r.getNetworkByNodeNameIndexer(ctx, OverlayNodeName)
		if err != nil {
			return "", fmt.Errorf("unable to get overlay network by node name indexer: %v", err)
		}

		if len(overlayNetworkName) == 0 {
			return "", fmt.Errorf("unable to find overlay network")
		}

		return overlayNetworkName, nil
	case types.GlobalBGP:
		// try to get global bgp network by special node name
		globalBGPNetworkName, err := r.getNetworkByNodeNameIndexer(ctx, GlobalBGPNodeName)
		if err != nil {
			return "", fmt.Errorf("unable to get overlay network by node name indexer: %v", err)
		}

		if len(globalBGPNetworkName) == 0 {
			return "", fmt.Errorf("unable to find global bgp network")
		}

		return globalBGPNetworkName, nil
	default:
		return "", fmt.Errorf("unknown network type %s from pod", networkType)
	}
}

func (r *PodReconciler) getNetworkByNodeNameIndexer(ctx context.Context, nodeName string) (string, error) {
	var networkList *networkingv1.NetworkList
	var err error
	if networkList, err = utils.ListNetworks(ctx, r, client.MatchingFields{IndexerFieldNode: nodeName}); err != nil {
		return "", fmt.Errorf("unable to list network by indexer node name %v: %v", nodeName, err)
	}

	// only use the first one
	if len(networkList.Items) >= 1 {
		return networkList.Items[0].GetName(), nil
	}
	return "", nil
}

// statefulAllocate means an allocation on a stateful pod, including some
// special features, ip retain, ip reuse or ip assignment
func (r *PodReconciler) statefulAllocate(ctx context.Context, pod *corev1.Pod, networkName string) (err error) {
	var (
		shouldObserve = true
		startTime     = time.Now()
	)

	defer func() {
		if shouldObserve {
			metrics.IPAllocationPeriodSummary.
				WithLabelValues(metrics.IPStatefulAllocateType, strconv.FormatBool(err == nil)).
				Observe(float64(time.Since(startTime).Nanoseconds()))
		}
	}()

	if err = r.addFinalizer(ctx, pod); err != nil {
		return wrapError("unable to add finalizer for stateful pod", err)
	}

	// preAssign means that user want to assign some IPs to pod through annotation
	var preAssign = len(pod.Annotations[constants.AnnotationIPPool]) > 0

	// expectReallocate means that ip is expected to be released and allocated again, usually
	// this will be set true when ip is leaking
	// 1. global retain and pod retain or unset, ip should be retained
	// 2. global retain and pod not retain, ip should be reallocated
	// 3. global not retain and pod not retain or unset, ip should be reallocated
	// 4. global not retain and pod retain, ip should be retained
	var expectReallocate = !globalutils.ParseBoolOrDefault(pod.Annotations[constants.AnnotationIPRetain], strategy.DefaultIPRetain)

	// shouldReallocate means that ip should be released and allocated again
	// if pre-assigned through annotation, this must be false
	var shouldReallocate = expectReallocate && !preAssign

	if shouldReallocate {
		var allocatedIPs []*networkingv1.IPInstance
		if allocatedIPs, err = utils.ListAllocatedIPInstancesOfPod(ctx, r, pod); err != nil {
			return err
		}

		// reallocate means that the allocated ones should be recycled firstly
		if len(allocatedIPs) > 0 {
			if err = r.release(ctx, pod, transform.TransferIPInstancesForIPAM(allocatedIPs)); err != nil {
				return wrapError("unable to release before reallocate", err)
			}
		}

		return wrapError("unable to reallocate", r.allocate(ctx, pod, networkName))
	}

	var (
		ipCandidates []ipCandidate
		forceAssign  = false
	)
	if preAssign {
		ipPool := strings.Split(pod.Annotations[constants.AnnotationIPPool], ",")
		idx := utils.GetIndexFromName(pod.Name)

		if idx >= len(ipPool) {
			return fmt.Errorf("unable to find assigned ip in ip-pool %s by index %d", pod.Annotations[constants.AnnotationIPPool], idx)
		}

		if len(ipPool[idx]) == 0 {
			return fmt.Errorf("the %d assigned ip is empty in ip-pool %s", idx, pod.Annotations[constants.AnnotationIPPool])
		}

		for _, ipStr := range strings.Split(ipPool[idx], "/") {
			// pre assignment only have IP
			ipCandidates = append(ipCandidates, ipCandidate{
				ip: globalutils.NormalizedIP(ipStr),
			})
		}
		// pre assignment can force using reserved IPs
		forceAssign = true
	} else {
		var allocatedIPInstances []*networkingv1.IPInstance
		if allocatedIPInstances, err = utils.ListAllocatedIPInstancesOfPod(ctx, r, pod); err != nil {
			return err
		}

		// allocated reuse will have both subnet and IP, also IP candidates should follow
		// ip family order, ipv4 before ipv6
		for i := range allocatedIPInstances {
			var ipInstance = allocatedIPInstances[i]
			if networkingv1.IsIPv6IPInstance(ipInstance) {
				ipCandidates = append(ipCandidates, ipCandidate{
					subnet: ipInstance.Spec.Subnet,
					ip:     utils.ToIPFormat(ipInstance.Name),
				})
			} else {
				ipCandidates = append([]ipCandidate{
					{
						subnet: ipInstance.Spec.Subnet,
						ip:     utils.ToIPFormat(ipInstance.Name),
					},
				}, ipCandidates...)
			}
		}

		// when no valid ip found, it means that this is the first time of pod creation
		if len(ipCandidates) == 0 {
			// allocate has its own observation process, so just skip
			shouldObserve = false
			return wrapError("unable to allocate", r.allocate(ctx, pod, networkName))
		}
	}

	// assign IP candidates to pod
	return wrapError("unable to assign", r.assign(ctx, pod, networkName, ipCandidates, forceAssign))
}

// assign means some allocated or pre-assigned IPs will be assigned to a specified pod
func (r *PodReconciler) assign(ctx context.Context, pod *corev1.Pod, networkName string, ipCandidates []ipCandidate, force bool) (err error) {
	// try to assign candidate IPs to pod
	var AssignedIPs []*types.IP
	if AssignedIPs, err = r.IPAMManager.Assign(networkName,
		ipamtypes.PodInfo{
			NamespacedName: apitypes.NamespacedName{
				Namespace: pod.Namespace,
				Name:      pod.Name,
			},
			IPFamily: types.ParseIPFamilyFromString(pod.Annotations[constants.AnnotationIPFamily]),
		},
		ipCandidateToAssignSuite(ipCandidates),
		ipamtypes.AssignForce(force),
	); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = r.IPAMManager.Release(networkName, ipToReleaseSuite(AssignedIPs))
		}
	}()

	if err = r.IPAMStore.ReCouple(ctx, pod, AssignedIPs); err != nil {
		return fmt.Errorf("fail to force-couple IPs %+v with pod: %v", AssignedIPs, err)
	}

	// always keep updating pod ip cache the final step
	r.PodIPCache.Record(pod.UID, pod.Name, pod.Namespace, ipToIPInstanceName(AssignedIPs))

	r.Recorder.Eventf(pod, corev1.EventTypeNormal, ReasonIPAllocationSucceed, "assign IPs %v successfully", ipToIPString(AssignedIPs))
	return nil
}

// release will release IP instances of pod
func (r *PodReconciler) release(ctx context.Context, pod *corev1.Pod, allocatedIPs []*types.IP) (err error) {
	for _, ip := range allocatedIPs {
		if err = r.IPAMStore.IPRecycle(ctx, pod.Namespace, ip); err != nil {
			return fmt.Errorf("unable to recycle ip %v: %v", ip, err)
		}
	}

	r.Recorder.Eventf(pod, corev1.EventTypeNormal, ReasonIPReleaseSucceed, "release IPs %v successfully", ipToIPString(allocatedIPs))
	return nil
}

// allocate will allocate new IPs for pod
func (r *PodReconciler) allocate(ctx context.Context, pod *corev1.Pod, networkName string) (err error) {
	var startTime = time.Now()
	defer func() {
		metrics.IPAllocationPeriodSummary.
			WithLabelValues(metrics.IPNormalAllocateType, strconv.FormatBool(err == nil)).
			Observe(float64(time.Since(startTime).Nanoseconds()))
	}()

	var (
		specifiedSubnetNames []string
		allocatedIPs         []*types.IP
		ipFamily             = types.ParseIPFamilyFromString(pod.Annotations[constants.AnnotationIPFamily])
	)
	if subnetNameStr := globalutils.PickFirstNonEmptyString(pod.Annotations[constants.AnnotationSpecifiedSubnet], pod.Labels[constants.LabelSpecifiedSubnet]); len(subnetNameStr) > 0 {
		specifiedSubnetNames = strings.Split(subnetNameStr, "/")
	}

	if allocatedIPs, err = r.IPAMManager.Allocate(networkName, ipamtypes.PodInfo{
		NamespacedName: apitypes.NamespacedName{
			Namespace: pod.Namespace,
			Name:      pod.Name,
		},
		IPFamily: ipFamily,
	}, ipamtypes.AllocateSubnets(specifiedSubnetNames)); err != nil {
		return fmt.Errorf("unable to allocate IP on family %s : %v", ipFamily, err)
	}

	defer func() {
		if err != nil {
			_ = r.IPAMManager.Release(networkName, ipToReleaseSuite(allocatedIPs))
		}
	}()

	if err = r.IPAMStore.Couple(ctx, pod, allocatedIPs); err != nil {
		return fmt.Errorf("unable to couple IPs %v with pod: %v", allocatedIPs, err)
	}

	// Always keep updating pod ip cache the final step.
	r.PodIPCache.Record(pod.UID, pod.Name, pod.Namespace, ipToIPInstanceName(allocatedIPs))

	r.Recorder.Eventf(pod, corev1.EventTypeNormal, ReasonIPAllocationSucceed, "allocate IPs %v successfully", ipToIPString(allocatedIPs))
	return nil
}

func (r *PodReconciler) addFinalizer(ctx context.Context, pod *corev1.Pod) error {
	if controllerutil.ContainsFinalizer(pod, constants.FinalizerIPAllocated) {
		return nil
	}

	patch := client.StrategicMergeFrom(pod.DeepCopy())
	controllerutil.AddFinalizer(pod, constants.FinalizerIPAllocated)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return r.Patch(ctx, pod, patch)
	})
}

func (r *PodReconciler) removeFinalizer(ctx context.Context, pod *corev1.Pod) error {
	if !controllerutil.ContainsFinalizer(pod, constants.FinalizerIPAllocated) {
		return nil
	}

	patch := client.StrategicMergeFrom(pod.DeepCopy())
	controllerutil.RemoveFinalizer(pod, constants.FinalizerIPAllocated)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return r.Patch(ctx, pod, patch)
	})
}

func ipToReleaseSuite(ips []*types.IP) (ret []ipamtypes.SubnetIPSuite) {
	for _, ip := range ips {
		ret = append(ret, ipamtypes.ReleaseIPOfSubnet(ip.Subnet, ip.Address.IP.String()))
	}
	return
}

func ipToIPInstanceName(ips []*types.IP) (ret []string) {
	for _, ip := range ips {
		ret = append(ret, utils.ToDNSFormat(ip.Address.IP))
	}
	return
}

func ipToIPString(ips []*types.IP) (ret []string) {
	for _, ip := range ips {
		ret = append(ret, ip.Address.IP.String())
	}
	return
}

func ipCandidateToAssignSuite(ipCandidates []ipCandidate) (ret []types.SubnetIPSuite) {
	for _, ipCandidate := range ipCandidates {
		if len(ipCandidate.subnet) == 0 {
			ret = append(ret, ipamtypes.AssignIP(ipCandidate.ip))
		} else {
			ret = append(ret, ipamtypes.AssignIPOfSubnet(ipCandidate.subnet, ipCandidate.ip))
		}
	}
	return
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) (err error) {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerPod).
		For(&corev1.Pod{},
			builder.WithPredicates(
				&utils.IgnoreDeletePredicate{},
				&predicate.ResourceVersionChangedPredicate{},
				predicate.NewPredicateFuncs(func(obj client.Object) bool {
					pod, ok := obj.(*corev1.Pod)
					if !ok {
						return false
					}
					// ignore host networking pod
					if pod.Spec.HostNetwork {
						return false
					}

					if pod.DeletionTimestamp.IsZero() {
						// only pod after scheduling should be processed
						return len(pod.Spec.NodeName) > 0
					}

					// terminating pods owned by stateful workloads should be processed for IP reservation
					return strategy.OwnByStatefulWorkload(pod)
				}),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.Max(),
		}).
		Complete(r)
}
