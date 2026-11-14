package kube

import "fmt"

// progressDeadlineExceeded is the reason a Deployment's Progressing condition
// carries once its rollout has made no progress within
// progressDeadlineSeconds (kubectl v0.37.2, pkg/util/deployment/deployment.go,
// TimedOutReason).
const progressDeadlineExceeded = "ProgressDeadlineExceeded"

// RolloutState is a port of kubectl v0.37.2's DeploymentStatusViewer.Status
// (k8s.io/kubectl/pkg/polymorphichelpers/rollout_status.go, kubectl v0.37.2),
// the rules `kubectl rollout status` waits on (§4). kubectl's revision argument
// is not ported: rollout status passes none.
//
//  1. While metadata.generation is ahead of status.observedGeneration, the
//     spec update is not yet observed, and nothing else is judged.
//  2. A Progressing condition with reason ProgressDeadlineExceeded is an
//     error wrapping ErrRolloutStalled.
//  3. Fewer updated replicas than spec.replicas is waiting.
//  4. More replicas than updated ones is waiting: old ones are terminating.
//  5. Fewer available replicas than updated ones is waiting.
//  6. Otherwise the rollout is done.
//
// waiting is "" when done or on error.
func RolloutState(d Deployment) (done bool, waiting string, err error) {
	if d.Metadata.Generation > d.Status.ObservedGeneration {
		return false, "waiting for the deployment spec update to be observed", nil
	}
	if c := deploymentCondition(d.Status, "Progressing"); c != nil && c.Reason == progressDeadlineExceeded {
		return false, "", refuse(ErrRolloutStalled, "deployment %q exceeded its progress deadline", d.Metadata.Name)
	}
	s := d.Status
	if d.Spec.Replicas != nil && s.UpdatedReplicas < *d.Spec.Replicas {
		return false, fmt.Sprintf("%d out of %d new replicas have been updated", s.UpdatedReplicas, *d.Spec.Replicas), nil
	}
	if s.Replicas > s.UpdatedReplicas {
		return false, fmt.Sprintf("%d old replicas are pending termination", s.Replicas-s.UpdatedReplicas), nil
	}
	if s.AvailableReplicas < s.UpdatedReplicas {
		return false, fmt.Sprintf("%d of %d updated replicas are available", s.AvailableReplicas, s.UpdatedReplicas), nil
	}
	return true, "", nil
}

// deploymentCondition is deploymentutil.GetDeploymentCondition (kubectl
// v0.37.2): the first condition of the type, or nil.
func deploymentCondition(s DeploymentStatus, condType string) *DeploymentCondition {
	for i := range s.Conditions {
		if s.Conditions[i].Type == condType {
			return &s.Conditions[i]
		}
	}
	return nil
}
