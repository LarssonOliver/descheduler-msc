/*
Copyright 2022 The Kubernetes Authors.

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

package nodecompactor

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/descheduler/pkg/framework"

	podutil "sigs.k8s.io/descheduler/pkg/descheduler/pod"
)

const PluginName = "NodeCompactor"

var _ framework.BalancePlugin = &NodeCompactor{}

// NodeCompactor evicts pods on the node that violate the max pod lifetime threshold
type NodeCompactor struct {
	handle    framework.Handle
	args      *NodeCompactorArgs
	podFilter podutil.FilterFunc
}

// New builds plugin from its arguments while passing a handle
func New(args runtime.Object, handle framework.Handle) (framework.Plugin, error) {
	nodeCompactorArgs, ok := args.(*NodeCompactorArgs)
	if !ok {
		return nil, fmt.Errorf("want args to be of type NodeCompactorArgs, got %T", args)
	}

	var includedNamespaces, excludedNamespaces sets.String
	if nodeCompactorArgs.Namespaces != nil {
		includedNamespaces = sets.NewString(nodeCompactorArgs.Namespaces.Include...)
		excludedNamespaces = sets.NewString(nodeCompactorArgs.Namespaces.Exclude...)
	}

	// We can combine Filter and PreEvictionFilter since for this strategy it does not matter where we run PreEvictionFilter
	podFilter, err := podutil.NewOptions().
		WithFilter(podutil.WrapFilterFuncs(handle.Evictor().Filter, handle.Evictor().PreEvictionFilter)).
		WithNamespaces(includedNamespaces).
		WithoutNamespaces(excludedNamespaces).
		// WithLabelSelector(nodeCompactorArgs.LabelSelector).
		BuildFilterFunc()
	if err != nil {
		return nil, fmt.Errorf("error initializing pod filter function: %v", err)
	}

	// podFilter = podutil.WrapFilterFuncs(podFilter, func(pod *v1.Pod) bool {
	// 	// podAgeSeconds := uint(metav1.Now().Sub(pod.GetCreationTimestamp().Local()).Seconds())
	// 	// return podAgeSeconds > *nodeCompactorArgs.MaxNodeCompactorSeconds
	// })

	// if len(nodeCompactorArgs.States) > 0 {
	// 	states := sets.NewString(nodeCompactorArgs.States...)
	// 	podFilter = podutil.WrapFilterFuncs(podFilter, func(pod *v1.Pod) bool {
	// 		if states.Has(string(pod.Status.Phase)) {
	// 			return true
	// 		}

	// 		for _, containerStatus := range pod.Status.ContainerStatuses {
	// 			if containerStatus.State.Waiting != nil && states.Has(containerStatus.State.Waiting.Reason) {
	// 				return true
	// 			}
	// 		}

	// 		return false
	// 	})
	// }

	return &NodeCompactor{
		handle:    handle,
		podFilter: podFilter,
		args:      nodeCompactorArgs,
	}, nil
}

// Name retrieves the plugin name
func (d *NodeCompactor) Name() string {
	return PluginName
}

// Deschedule extension point implementation for the plugin
func (d *NodeCompactor) Balance(ctx context.Context, nodes []*v1.Node) *framework.Status {
	// podsToEvict := make([]*v1.Pod, 0)
	// nodeMap := make(map[string]*v1.Node, len(nodes))

	klog.V(1).InfoS("NodeCompactor test")

	// for _, node := range nodes {
	// 	klog.V(1).InfoS("Processing node", "node", klog.KObj(node))
	// 	pods, err := podutil.ListAllPodsOnANode(node.Name, d.handle.GetPodsAssignedToNodeFunc(), d.podFilter)
	// 	if err != nil {
	// 		// no pods evicted as error encountered retrieving evictable Pods
	// 		return &framework.Status{
	// 			Err: fmt.Errorf("error listing pods on a node: %v", err),
	// 		}
	// 	}

	// 	nodeMap[node.Name] = node
	// 	podsToEvict = append(podsToEvict, pods...)
	// }

	// Should sort Pods so that the oldest can be evicted first
	// in the event that PDB or settings such maxNoOfPodsToEvictPer* prevent too much eviction
	// podutil.SortPodsBasedOnAge(podsToEvict)

	// for _, pod := range podsToEvict {
	// 	if !d.handle.Evictor().NodeLimitExceeded(nodeMap[pod.Spec.NodeName]) {
	// 		d.handle.Evictor().Evict(ctx, pod, evictions.EvictOptions{})
	// 	}
	// }

	return nil
}
