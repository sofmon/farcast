package kube

import (
	"errors"
	"testing"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

func deployment(generation, observed int64, replicas *int32, status DeploymentStatus) Deployment {
	status.ObservedGeneration = observed
	return Deployment{
		Metadata: ObjectMeta{ObjectMeta: tkube.ObjectMeta{Name: "api", Namespace: "web"}, Generation: generation},
		Spec:     WorkloadSpec{Replicas: replicas},
		Status:   status,
	}
}

func int32p(n int32) *int32 { return &n }

// TestRolloutStatusFollowsTheSixRules is kubectl v0.37.2's
// DeploymentStatusViewer, rule by rule: rule 1 is judged first, and rules 2
// to 6 only once it has passed.
func TestRolloutStatusFollowsTheSixRules(t *testing.T) {
	deadline := []DeploymentCondition{{Type: "Progressing", Status: "False", Reason: "ProgressDeadlineExceeded", Message: "ReplicaSet has timed out progressing."}}
	progressing := []DeploymentCondition{
		{Type: "Available", Status: "True", Reason: "MinimumReplicasAvailable"},
		{Type: "Progressing", Status: "True", Reason: "NewReplicaSetAvailable"},
	}
	cases := []struct {
		name        string
		d           Deployment
		done        bool
		waiting     string
		wantStalled bool
	}{
		{"1: the spec update is not yet observed",
			deployment(3, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}),
			false, "waiting for the deployment spec update to be observed", false},
		{"1 before 2: an unobserved spec waits, even past the deadline",
			deployment(3, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2, Conditions: deadline}),
			false, "waiting for the deployment spec update to be observed", false},
		{"1 before 6: an unobserved spec is never done",
			deployment(2, 1, nil, DeploymentStatus{}),
			false, "waiting for the deployment spec update to be observed", false},
		{"2: the progress deadline exceeded",
			deployment(2, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 1, Conditions: deadline}),
			false, "", true},
		{"2 reads only Progressing's reason",
			deployment(2, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2,
				Conditions: []DeploymentCondition{{Type: "Available", Status: "False", Reason: "ProgressDeadlineExceeded"}}}),
			true, "", false},
		{"3: fewer updated than desired",
			deployment(2, 2, int32p(3), DeploymentStatus{Replicas: 3, UpdatedReplicas: 1, AvailableReplicas: 1, Conditions: progressing}),
			false, "1 out of 3 new replicas have been updated", false},
		{"3 is skipped without spec.replicas",
			deployment(2, 2, nil, DeploymentStatus{Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}),
			true, "", false},
		{"4: old replicas pending termination",
			deployment(2, 2, int32p(2), DeploymentStatus{Replicas: 3, UpdatedReplicas: 2, AvailableReplicas: 2}),
			false, "1 old replicas are pending termination", false},
		{"5: updated replicas not yet available",
			deployment(2, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 1}),
			false, "1 of 2 updated replicas are available", false},
		{"6: done",
			deployment(2, 2, int32p(2), DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2, Conditions: progressing}),
			true, "", false},
		{"6: an observed generation ahead of the spec counts as observed, as kubectl's <= does",
			deployment(2, 5, int32p(1), DeploymentStatus{Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}),
			true, "", false},
		{"6: scaled to zero",
			deployment(4, 4, int32p(0), DeploymentStatus{}),
			true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done, waiting, err := RolloutState(tc.d)
			if tc.wantStalled {
				if !errors.Is(err, ErrRolloutStalled) {
					t.Fatalf("err = %v, want ErrRolloutStalled", err)
				}
				if want := `deployment "api" exceeded its progress deadline`; err.Error() != want {
					t.Errorf("error = %q, want %q", err.Error(), want)
				}
			} else if err != nil {
				t.Fatalf("err = %v", err)
			}
			if done != tc.done || waiting != tc.waiting {
				t.Errorf("RolloutState = %v, %q; want %v, %q", done, waiting, tc.done, tc.waiting)
			}
		})
	}
}
