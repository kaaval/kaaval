module kaaval/cloud-scanner

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.32.7
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.285.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.77.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6
	github.com/aws/smithy-go v1.24.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.11.1
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/apimachinery v0.35.0
	k8s.io/client-go v0.35.0
)
