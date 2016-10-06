package volume

import (
	"fmt"
	"strings"

	"github.com/openshift/origin/pkg/security/uid"
	"k8s.io/client-go/1.4/pkg/api/v1"
	"k8s.io/client-go/1.4/pkg/apis/extensions"
)

const UIDRangeAnnotation = "openshift.io/sa.scc.uid-range"
const SupplementalGroupsAnnotation = "openshift.io/sa.scc.supplemental-groups"
const ValidatedSCCAnnotation = "openshift.io/scc"

// // Generate creates the group based on policy rules.  By default this returns the first group of the
// // first range (min val).
// func (s *mustRunAs) Generate(pod *api.Pod) ([]int64, error) {
// 	return []int64{s.ranges[0].Min}, nil
// }

// getSupplementalGroupsAnnotation provides a backwards compatible way to get supplemental groups
// annotations from a namespace by looking for SupplementalGroupsAnnotation and falling back to
// UIDRangeAnnotation if it is not found.
func getSupplementalGroupsAnnotation(ns *v1.Namespace) (string, error) {
	groups, ok := ns.Annotations[SupplementalGroupsAnnotation]
	if !ok {
		// glog.V(4).Infof("unable to find supplemental group annotation %s falling back to %s", allocator.SupplementalGroupsAnnotation, allocator.UIDRangeAnnotation)

		groups, ok = ns.Annotations[UIDRangeAnnotation]
		if !ok {
			return "", fmt.Errorf("unable to find supplemental group or uid annotation for namespace %s", ns.Name)
		}
	}

	if len(groups) == 0 {
		return "", fmt.Errorf("unable to find groups using %s and %s annotations", SupplementalGroupsAnnotation, UIDRangeAnnotation)
	}
	return groups, nil
}

func (p *nfsProvisioner) getPreallocatedSupplementalGroups(ns *v1.Namespace) ([]extensions.IDRange, error) {
	groups, err := getSupplementalGroupsAnnotation(ns)
	if err != nil {
		return nil, err
	}
	// glog.V(4).Infof("got preallocated value for groups: %s in namespace %s", groups, ns.Name)

	blocks, err := parseSupplementalGroupAnnotation(groups)
	if err != nil {
		return nil, err
	}

	idRanges := []extensions.IDRange{}
	for _, block := range blocks {
		rng := extensions.IDRange{
			Min: int64(block.Start),
			Max: int64(block.End),
		}
		idRanges = append(idRanges, rng)
	}
	return idRanges, nil
}

// parseSupplementalGroupAnnotation parses the group annotation into blocks.
func parseSupplementalGroupAnnotation(groups string) ([]uid.Block, error) {
	blocks := []uid.Block{}
	segments := strings.Split(groups, ",")
	for _, segment := range segments {
		block, err := uid.ParseBlock(segment)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no blocks parsed from annotation %s", groups)
	}
	return blocks, nil
}

// // requiresPreAllocatedSELinuxLevel returns true if the strategy is must run as and there is no
// // range specified.
// func requiresPreallocatedSupplementalGroups(constraint *v1.SecurityContextConstraints) bool {
// 	if constraint.SupplementalGroups.Type != v1.SupplementalGroupsStrategyMustRunAs {
// 		return false
// 	}
// 	return len(constraint.SupplementalGroups.Ranges) == 0
// }
