package kubernetes.admission

test_policy_deny_image_source {
	deny["pod \"myapp\" has invalid registry \"nginx\""] with input as {"kind":"AdmissionReview","request":{"operation":"CREATE","kind":{"kind":"Pod","version":"v1"},"object":{"metadata":{"name":"myapp"},"spec":{"containers":[{"image":"nginx","name":"nginx-frontend"}]}}}}
}

test_policy_allow_image_source {
	count(deny) == 0 with input as {"kind":"AdmissionReview","request":{"operation":"CREATE","kind":{"kind":"Pod","version":"v1"},"object":{"metadata":{"name":"myapp"},"spec":{"containers":[{"image":"602401143452.dkr.ecr.amazonaws.com/nginx","name":"nginx-frontend"}]}}}}
}