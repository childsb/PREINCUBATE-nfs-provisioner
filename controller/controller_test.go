/*
Copyright 2016 Red Hat, Inc.

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

package controller

import (
	"k8s.io/client-go/1.5/kubernetes/fake"
	"k8s.io/client-go/1.5/pkg/api"
	"k8s.io/client-go/1.5/pkg/api/resource"
	"k8s.io/client-go/1.5/pkg/api/testapi"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/storage/v1beta1"
	"k8s.io/client-go/1.5/pkg/runtime"
	"k8s.io/client-go/1.5/pkg/types"

	"reflect"
	"testing"
	"time"
)

// TODO failed provision, failed pv save, failed delete, failed pv delete?

func TestController(t *testing.T) {
	tests := []struct {
		name            string
		objs            []runtime.Object
		provisionerName string
		expectedVolumes []v1.PersistentVolume
	}{
		{
			name: "2 classes, 1 claim each. provision 1",
			objs: []runtime.Object{
				newStorageClass("class-1", "foo.bar/baz"),
				newStorageClass("class-2", "abc.def/ghi"),
				newClaim("claim-1", "uid-1-1", "class-1", ""),
				newClaim("claim-2", "uid-1-2", "class-2", ""),
			},
			provisionerName: "foo.bar/baz",
			expectedVolumes: []v1.PersistentVolume{
				*newProvisionedVolume(newStorageClass("class-1", "foo.bar/baz"), newClaim("claim-1", "uid-1-1", "class-1", "")),
			},
		},
		{
			name: "2 volumes. delete 1",
			objs: []runtime.Object{
				newVolume("volume-1", v1.VolumeReleased, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "foo.bar/baz"}),
				newVolume("volume-2", v1.VolumeReleased, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "abc.def/ghi"}),
			},
			provisionerName: "foo.bar/baz",
			expectedVolumes: []v1.PersistentVolume{
				*newVolume("volume-2", v1.VolumeReleased, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "abc.def/ghi"}),
			},
		},
	}
	for _, test := range tests {
		client := fake.NewSimpleClientset(test.objs...)
		resyncPeriod := 100 * time.Millisecond
		provisioner := newTestProvisioner()
		ctrl := NewProvisionController(client, resyncPeriod, test.provisionerName, provisioner)

		ctrl.createProvisionedPVInterval = 10 * time.Millisecond

		stopCh := make(chan struct{})
		go ctrl.Run(stopCh)

		time.Sleep(2 * resyncPeriod)
		ctrl.runningOperations.Wait()

		pvList, _ := client.Core().PersistentVolumes().List(api.ListOptions{})
		if !reflect.DeepEqual(test.expectedVolumes, pvList.Items) {
			t.Logf("test case: %s", test.name)
			t.Errorf("expected PVs:\n %v\n but got:\n %v\n", test.expectedVolumes, pvList.Items)
		}
		close(stopCh)
	}
}

func TestShouldProvision(t *testing.T) {
	tests := []struct {
		name            string
		provisionerName string
		class           *v1beta1.StorageClass
		claim           *v1.PersistentVolumeClaim
		expectedShould  bool
	}{
		{
			name:            "should provision",
			provisionerName: "foo.bar/baz",
			class:           newStorageClass("class-1", "foo.bar/baz"),
			claim:           newClaim("claim-1", "1-1", "class-1", ""),
			expectedShould:  true,
		},
		{
			name:            "claim already bound",
			provisionerName: "foo.bar/baz",
			class:           newStorageClass("class-1", "foo.bar/baz"),
			claim:           newClaim("claim-1", "1-1", "class-1", "foo"),
			expectedShould:  false,
		},
		{
			name:            "no such class",
			provisionerName: "foo.bar/baz",
			class:           newStorageClass("class-1", "foo.bar/baz"),
			claim:           newClaim("claim-1", "1-1", "class-2", ""),
			expectedShould:  false,
		},
		{
			name:            "not this provisioner's job",
			provisionerName: "foo.bar/baz",
			class:           newStorageClass("class-1", "abc.def/ghi"),
			claim:           newClaim("claim-1", "1-1", "class-1", ""),
			expectedShould:  false,
		},
	}
	for _, test := range tests {
		client := fake.NewSimpleClientset(test.claim)
		resyncPeriod := 100 * time.Millisecond
		provisioner := newTestProvisioner()
		ctrl := NewProvisionController(client, resyncPeriod, test.provisionerName, provisioner)

		err := ctrl.classes.Add(test.class)
		if err != nil {
			t.Logf("test case: %s", test.name)
			t.Errorf("error adding class %v to cache: %v", test.class, err)
		}

		should := ctrl.shouldProvision(test.claim)
		if test.expectedShould != should {
			t.Logf("test case: %s", test.name)
			t.Errorf("expected should provision %v but got %v\n", test.expectedShould, should)
		}
	}
}

func TestShouldDelete(t *testing.T) {
	tests := []struct {
		name            string
		provisionerName string
		volume          *v1.PersistentVolume
		expectedShould  bool
	}{
		{
			name:            "should delete",
			provisionerName: "foo.bar/baz",
			volume:          newVolume("volume-1", v1.VolumeReleased, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "foo.bar/baz"}),
			expectedShould:  true,
		},
		// TODO 1.4 we should delete volumeFailed, 1.5 we should not
		{
			name:            "bound phase",
			provisionerName: "foo.bar/baz",
			volume:          newVolume("volume-1", v1.VolumeBound, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "foo.bar/baz"}),
			expectedShould:  false,
		},
		{
			name:            "non-delete reclaim policy",
			provisionerName: "foo.bar/baz",
			volume:          newVolume("volume-1", v1.VolumeReleased, v1.PersistentVolumeReclaimRetain, map[string]string{annDynamicallyProvisioned: "foo.bar/baz"}),
			expectedShould:  false,
		},
		{
			name:            "not this provisioner's job",
			provisionerName: "foo.bar/baz",
			volume:          newVolume("volume-1", v1.VolumeReleased, v1.PersistentVolumeReclaimDelete, map[string]string{annDynamicallyProvisioned: "abc.def/ghi"}),
			expectedShould:  false,
		},
	}
	for _, test := range tests {
		client := fake.NewSimpleClientset()
		resyncPeriod := 100 * time.Millisecond
		provisioner := newTestProvisioner()
		ctrl := NewProvisionController(client, resyncPeriod, test.provisionerName, provisioner)

		should := ctrl.shouldDelete(test.volume)
		if test.expectedShould != should {
			t.Logf("test case: %s", test.name)
			t.Errorf("expected should delete %v but got %v\n", test.expectedShould, should)
		}
	}
}

func newStorageClass(name, provisioner string) *v1beta1.StorageClass {
	return &v1beta1.StorageClass{
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
		Provisioner: provisioner,
	}
}

func newClaim(name, claimUID, provisioner, volumeName string) *v1.PersistentVolumeClaim {
	return &v1.PersistentVolumeClaim{
		ObjectMeta: v1.ObjectMeta{
			Name:            name,
			Namespace:       "default",
			UID:             types.UID(claimUID),
			ResourceVersion: "1",
			Annotations:     map[string]string{annClass: provisioner},
			SelfLink:        testapi.Default.SelfLink("pvc", ""),
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{v1.ReadWriteOnce, v1.ReadOnlyMany},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					v1.ResourceName(v1.ResourceStorage): resource.MustParse("1Mi"),
				},
			},
			VolumeName: volumeName,
		},
		Status: v1.PersistentVolumeClaimStatus{
			Phase: v1.ClaimPending,
		},
	}
}

func newVolume(name string, phase v1.PersistentVolumePhase, policy v1.PersistentVolumeReclaimPolicy, annotations map[string]string) *v1.PersistentVolume {
	pv := &v1.PersistentVolume{
		ObjectMeta: v1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: v1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: policy,
			AccessModes:                   []v1.PersistentVolumeAccessMode{v1.ReadWriteOnce, v1.ReadOnlyMany},
			Capacity: v1.ResourceList{
				v1.ResourceName(v1.ResourceStorage): resource.MustParse("1Mi"),
			},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				NFS: &v1.NFSVolumeSource{
					Server:   "foo",
					Path:     "bar",
					ReadOnly: false,
				},
			},
		},
		Status: v1.PersistentVolumeStatus{
			Phase: phase,
		},
	}

	return pv
}

// newProvisionedVolume returns the volume the test controller should provision for the
// given claim with the given class
func newProvisionedVolume(storageClass *v1beta1.StorageClass, claim *v1.PersistentVolumeClaim) *v1.PersistentVolume {
	options := VolumeOptions{
		Capacity:                      claim.Spec.Resources.Requests[v1.ResourceName(v1.ResourceStorage)],
		AccessModes:                   claim.Spec.AccessModes,
		PersistentVolumeReclaimPolicy: v1.PersistentVolumeReclaimDelete,
		PVName:     "pvc-" + string(claim.ObjectMeta.UID),
		Parameters: storageClass.Parameters,
	}
	volume, _ := newTestProvisioner().Provision(options)
	volume.Spec.ClaimRef, _ = v1.GetReference(claim)
	volume.Annotations = map[string]string{annDynamicallyProvisioned: storageClass.Provisioner, annClass: storageClass.Name}
	return volume
}

func newTestProvisioner() Provisioner {
	return &testProvisioner{}
}

type testProvisioner struct {
}

func (p *testProvisioner) Provision(options VolumeOptions) (*v1.PersistentVolume, error) {
	pv := &v1.PersistentVolume{
		ObjectMeta: v1.ObjectMeta{
			Name: options.PVName,
		},
		Spec: v1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: options.PersistentVolumeReclaimPolicy,
			AccessModes:                   options.AccessModes,
			Capacity: v1.ResourceList{
				v1.ResourceName(v1.ResourceStorage): options.Capacity,
			},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				NFS: &v1.NFSVolumeSource{
					Server:   "foo",
					Path:     "bar",
					ReadOnly: false,
				},
			},
		},
	}

	return pv, nil
}

func (p *testProvisioner) Delete(volume *v1.PersistentVolume) error {
	return nil
}
