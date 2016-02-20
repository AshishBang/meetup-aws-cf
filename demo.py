from troposphere import Base64, FindInMap, GetAtt, Tags, Join, Select, GetAZs
from troposphere import Parameter, Output, Ref, Template
import troposphere.ec2 as ec2
import troposphere.iam as iam
import troposphere.cloudformation as cfn
from troposphere.route53 import RecordSet, RecordSetGroup
import troposphere.elasticloadbalancing as elb

t = Template()
t.add_description("AWS Cloudformation Demo Stack")

KeyName = t.add_parameter(Parameter(
    "KeyName",
    Description="Name of an existing EC2 KeyPair to enable SSH "
                "access to the instance",
    Type='AWS::EC2::KeyPair::KeyName',
))

Bucket = t.add_parameter(Parameter(
    "Bucket",
    ConstraintDescription="GSLab demo bucket",
    Description="S3 Bucket",
    Default="gslab-demo",
    Type="String",
))

EC2InstanceType = t.add_parameter(Parameter(
  "EC2InstanceType",
  Description="Webserver instance type",
  Type="String",
  Default="t1.micro",
  AllowedValues=[ "t1.micro", "t2.small", "t2.medium", "m3.medium",
                  "m3.large", "m3.xlarge", "c3.large", "c3.xlarge",
                  "c4.large", "c4.xlarge"
                ]
))

VPCCIDR=t.add_parameter(Parameter(
  "VPCCIDR",
  Description="CIDR for vpc",
  MinLength="5",
  MaxLength="12",
  AllowedPattern="(\d{1,3})\.(\d{1,3})\.(\d{1,3})",
  Type="String",
  Default="10.200.0",
  ConstraintDescription="Must be a valid IP CIDR range of the form x.x.x.",
))

HostedZone=t.add_parameter(Parameter(
  "HostedZone",
  Description="Hosted zone for dns records",
  Type="String",
  Default="example.com",
  ConstraintDescription="Must be a valid hosted zone fqdn: example.com",
))

def AssumeRole():
    return {
        "Version" : "2012-10-17",
        "Statement": [ {
            "Effect": "Allow",
            "Principal": {
                "Service": [ "ec2.amazonaws.com" ]
            },
            "Action": [ "sts:AssumeRole" ]
        } ]
    }

def Allow(sid, action, resource, principal=None):
    s = {
        "Sid": sid,
        "Effect": "Allow",
        "Action": action,
        "Resource": resource
    }
    if(principal):
        s['Principal'] = principal
    return [ s ]

t.add_mapping('RegionMap', {
    "us-east-1": {"AMI": "ami-7f418316"},
    "us-west-1": {"AMI": "ami-951945d0"},
    "us-west-2": {"AMI": "ami-16fd7026"},
    "eu-west-1": {"AMI": "ami-24506250"},
    "sa-east-1": {"AMI": "ami-3e3be423"},
    "ap-southeast-1": {"AMI": "ami-acd9e8fe"},
    "ap-northeast-1": {"AMI": "ami-dcfa4edd"}
})

VPC = t.add_resource(ec2.VPC(
    "VPC",
    EnableDnsSupport="true",
    EnableDnsHostnames="true",
    CidrBlock=Join("",[Ref(VPCCIDR),".0/16"]),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "VPC" ]),
    )
))

InternetGateway = t.add_resource(ec2.InternetGateway(
    "InternetGateway",
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "IGW" ]),
    ),
))

AttachGateway = t.add_resource(ec2.VPCGatewayAttachment(
    "AttachGateway",
     VpcId=Ref(VPC),
     InternetGatewayId=Ref(InternetGateway),
))

PublicRouteTable = t.add_resource(ec2.RouteTable(
    "PublicRouteTable",
    VpcId=Ref(VPC),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "Public" ]),
    ),
))

PublicRoute = t.add_resource(ec2.Route(
    "PublicRoute",
    GatewayId=Ref("InternetGateway"),
    DestinationCidrBlock="0.0.0.0/0",
    RouteTableId=Ref("PublicRouteTable"),
))

PublicSubnetA = t.add_resource(ec2.Subnet(
    "PublicSubnetA",
    VpcId=Ref(VPC),
    CidrBlock=Join(".",[Ref(VPCCIDR),"0/28"]),
    AvailabilityZone=Select(0, GetAZs("")),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "Public" ]),
        VPC=Ref(VPC),
    )
))

PublicSubnetB = t.add_resource(ec2.Subnet(
    "PublicSubnetB",
    VpcId=Ref(VPC),
    CidrBlock=Join(".",[Ref(VPCCIDR),"16/28"]),
    AvailabilityZone=Select(1, GetAZs("")),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "Public" ]),
        VPC=Ref(VPC),
    )
))

PublicSubnetARouteTableAssociation = t.add_resource(ec2.SubnetRouteTableAssociation(
    "PublicSubnetARouteTableAssociation",
    SubnetId=Ref(PublicSubnetA),
    RouteTableId=Ref("PublicRouteTable"),
))

PublicSubnetBRouteTableAssociation = t.add_resource(ec2.SubnetRouteTableAssociation(
    "PublicSubnetBRouteTableAssociationB",
    SubnetId=Ref(PublicSubnetB),
    RouteTableId=Ref("PublicRouteTable"),
))

AvailabilityZone1=Select(0, GetAZs(""))
AvailabilityZone2=Select(1, GetAZs(""))

ELBPublicSubnetA=t.add_resource(ec2.Subnet(
  "ELBPublicSubnetA",
  CidrBlock=Join(".",[Ref(VPCCIDR),"32/28"]),
  VpcId=Ref(VPC),
  AvailabilityZone=AvailabilityZone1,
  Tags=Tags(
            Name=Join(" ",[Ref("AWS::StackName"), "ELBPublicSubnetA"]),
            VPC=Ref("VPC"),
           ),
  DependsOn=['AttachGateway']
))

ELBPublicSubnetB=t.add_resource(ec2.Subnet(
  "ELBPublicSubnetB",
  CidrBlock=Join(".",[Ref(VPCCIDR),"48/28"]),
  VpcId=Ref(VPC),
  AvailabilityZone=AvailabilityZone2,
  Tags=Tags(
            Name=Join(" ",[Ref("AWS::StackName"), "ELBPublicSubnetB"]),
            VPC=Ref("VPC"),
           ),
  DependsOn=['AttachGateway']
))

ELBPublicSubnetARouteTableAssociation=t.add_resource(ec2.SubnetRouteTableAssociation(
  "ELBPublicSubnetARouteTableAssociation",
  SubnetId=Ref(ELBPublicSubnetA),
  RouteTableId=Ref(PublicRouteTable)
))

ELBPublicSubnetBRouteTableAssociation=t.add_resource(ec2.SubnetRouteTableAssociation(
  "ELBPublicSubnetBRouteTableAssociation",
  SubnetId=Ref(ELBPublicSubnetB),
  RouteTableId=Ref(PublicRouteTable)
))


EIP1=t.add_resource(ec2.EIP(
  "EIP1",
  Domain="vpc",
  InstanceId=Ref("EC2Instance1"),
  DependsOn=["InternetGateway"]
))


EIP2=t.add_resource(ec2.EIP(
  "EIP2",
  Domain="vpc",
  InstanceId=Ref("EC2Instance2"),
  DependsOn=["InternetGateway"]
))

security_group =  t.add_resource(ec2.SecurityGroup(
    "SecurityGroup",
    SecurityGroupIngress=[
        { "ToPort": "22",   "IpProtocol": "tcp", "CidrIp": "0.0.0.0/0", "FromPort": "22" },
        { "ToPort": "443",  "IpProtocol": "tcp", "CidrIp": "0.0.0.0/0", "FromPort": "443"},
        { "ToPort": "80",   "IpProtocol": "tcp", "CidrIp": "0.0.0.0/0", "FromPort": "80" },
        { "ToPort":"80",    "FromPort":"80", "SourceSecurityGroupId":Ref("ElbSecurityGroup"), "IpProtocol":"tcp"},
        ],
    VpcId=Ref("VPC"),
    GroupDescription="Enable access to demo EC2 instance",
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "SecurityGroup" ]),
        VPC=Ref(VPC),
    )
))

ElbSecurityGroup=t.add_resource(ec2.SecurityGroup(
  "ElbSecurityGroup",
  GroupDescription="Security group for elb",
  SecurityGroupIngress=[
    {"ToPort":"80","FromPort":"80", "CidrIp":"0.0.0.0/0", "IpProtocol": "tcp"},
  ],
  VpcId=Ref(VPC),
  Tags=Tags(
            Name=Join(" ",[Ref("AWS::StackName"),"elbSecurityGroup"]),
            VPC=Ref(VPC),
           )
))

InstanceRole = t.add_resource(iam.Role(
    "InstanceRole",
    AssumeRolePolicyDocument=AssumeRole(),
    Path=Join("/", [ "", "DemoInstanceRole/" ]),
    Policies=[iam.Policy(PolicyName="DemoInstancePolicy",
                        PolicyDocument={
                                         "Version" : "2012-10-17",
                                         "Statement": Allow(
                                                              "StackS3List",
                                                              [
                                                                "s3:ListBucket",
                                                              ], [
                                                                "arn:aws:s3:::*"
                                                              ]
                                                      ) + Allow(
                                                                "StackS3Read",
                                                                [
                                                                    "s3:GetObject",
                                                                    "s3:GetBucketLocation",
                                                                    "s3:ListBucket"
                                                                ], [
                                                                    Join("", [ "arn:aws:s3:::", Ref(Bucket), "/*" ])
                                                                ]
                                                      ) 
                                       }
                       )
             ]
  )
)
#    
#
InstanceProfile  = t.add_resource(iam.InstanceProfile(
    "InstanceProfile",
    Path="/",
    Roles=[ Ref(InstanceRole) ]
))


def Meta(name, private_ip):
    return cfn.Metadata(
        cfn.Authentication({
            "default": cfn.AuthenticationBlock(type="S3", roleName=Ref(InstanceRole), buckets=[ Ref(Bucket) ])
        }),
        cfn.Init(
            cfn.InitConfigSets(default = ['SetupHost','SetupWebsite']),
            SetupHost = cfn.InitConfig(
                     files = {
                               "/etc/hostname":{
                                                 "content": Join(".",[ name, Ref(HostedZone) ])
                             },
                             "/root/set-hostname.sh":{
                                 "content": Join("",[
                                    "#!/bin/bash\n",
                                    "hostname --file /etc/hostname\n",
                                    "h=$(cat /etc/hostname)\n",
                                    "sed -i s/HOSTNAME=.*/HOSTNAME=$h/g /etc/sysconfig/network\n",
                                    "echo ", private_ip , " $h >>/etc/hosts \n",
                                    "service network restart"
                                 ]),
                                 "mode": "755"
                             },
                     },
                     commands={
                             "1-set-hostname": {
                                                 "command": "/root/set-hostname.sh "
                             }
                     }
            ),
            SetupWebsite = cfn.InitConfig(
                     packages = {
                                  "yum" : { 'httpd' : []}
                                },
                     sources =  {
                                  "/var/www/html/": Join("", [ "https://", Ref(Bucket), ".s3.amazonaws.com/3dstreetartindia.zip" ])
                                },
                     services = {
                                  "sysvinit" : {
                                                 "httpd"    : { "enabled" : "true", "ensureRunning" : "true" },
                                               }
                                }

            )
))

def UserData(name):
  return Base64(Join("", [
        "#!/bin/bash\n",
        "yum update -y aws-cfn-bootstrap\n",
        "function error_exit\n",
        "{\n",
        "  /opt/aws/bin/cfn-signal -e 1 -r \"$1\" '", Ref("WaitConditionHandle"), "'\n",
        "  exit 1\n",
        "}\n",
        "/opt/aws/bin/cfn-init -v -s ", Ref("AWS::StackId"), " -r ", name, " --region ", Ref("AWS::Region"),
        " || error_exit 'Failed to run cfn-init'\n"
        "/opt/aws/bin/cfn-signal -s true --reason \"", "Demo EC2 Instance setup complete\" '", Ref("WaitConditionHandle"), "' --region ", Ref("AWS::Region"), " \n"
    ]))

Instance1PrivateIp=Join("",[Ref(VPCCIDR),".5"])
Instance2PrivateIp=Join("",[Ref(VPCCIDR),".20"])

EC2Instance1 = t.add_resource(ec2.Instance(
    'EC2Instance1',
    ImageId=FindInMap("RegionMap", Ref("AWS::Region"), "AMI"),
    InstanceType=Ref(EC2InstanceType),
    KeyName=Ref(KeyName),
    SecurityGroupIds=[Ref(security_group)],
    SubnetId=Ref(PublicSubnetA),
    PrivateIpAddress=Instance1PrivateIp,
    IamInstanceProfile=Ref(InstanceProfile),
    Metadata=Meta('demo', Instance1PrivateIp),
    UserData=UserData('EC2Instance1'),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "Website EC2 Instance 1" ]),
        env='Demo'
    )
))

EC2Instance2 = t.add_resource(ec2.Instance(
    'EC2Instance2',
    ImageId=FindInMap("RegionMap", Ref("AWS::Region"), "AMI"),
    InstanceType=Ref(EC2InstanceType),
    KeyName=Ref(KeyName),
    SecurityGroupIds=[Ref(security_group)],
    SubnetId=Ref(PublicSubnetB),
    PrivateIpAddress=Instance2PrivateIp,
    IamInstanceProfile=Ref(InstanceProfile),
    Metadata=Meta('demo', Instance2PrivateIp),
    UserData=UserData('EC2Instance2'),
    Tags=Tags(
        Name=Join(" ", [ Ref("AWS::StackName"), "Website EC2 Instance 2" ]),
        env='Demo'
    )
))

WaitConditionHandle = t.add_resource(cfn.WaitConditionHandle("WaitConditionHandle"))

Wait4Instance = t.add_resource(cfn.WaitCondition(
    "Wait4Instance",
    Handle=Ref("WaitConditionHandle"),
    DependsOn=["EC2Instance1", "EC2Instance2"],
    Timeout="1200",
    Count="2"
))

ELB=t.add_resource(elb.LoadBalancer(
  "PublicLoadBalancer",
  ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
    Enabled=True,
    Timeout=300
  ),
  Subnets=[Ref(ELBPublicSubnetA), Ref(ELBPublicSubnetB)],
  HealthCheck=elb.HealthCheck(
    Target="TCP:80",
    Interval="30",
    Timeout="5",
    HealthyThreshold="5",
    UnhealthyThreshold="2"
  ),
  SecurityGroups=[Ref("ElbSecurityGroup")],
  Scheme="internet-facing",
  CrossZone=True,
  Listeners=[
              elb.Listener(
                LoadBalancerPort="80",
                InstancePort="80",
                Protocol="HTTP",
                InstanceProtocol="HTTP"
              )
            ],
  LoadBalancerName=Join("-",[Ref("AWS::StackName"),"ELB"]),
  Instances=[Ref(EC2Instance1), Ref(EC2Instance2) ],
  #DependsOn=["EC2Instance1", "EC2Instance2"]
  DependsOn=["Wait4Instance"]
))

PublicRecords=[
  RecordSet(
    Name=Join("",[ "demo.", Ref(HostedZone), "."]),
    Type="CNAME",
    TTL="400",
    ResourceRecords=[GetAtt("PublicLoadBalancer","DNSName")]
  )
 ]

PublicRecordSet=t.add_resource(RecordSetGroup(
  "PublicRecordSet",
  HostedZoneName=Join("",[Ref(HostedZone),"."]),
  Comment="Public Record sets",
  RecordSets=PublicRecords
))

t.add_output([
    Output(
        "InstanceId",
        Description="InstanceId of the newly created EC2 instance",
        Value=Ref(EC2Instance1),
    ),
    Output(
        "PublicIP",
        Description="Public IP address of the newly created EC2 instance",
        Value=GetAtt(EC2Instance1, "PublicIp"),
    ),
    Output(
        "PrivateIP",
        Description="Private IP address of the newly created EC2 instance",
        Value=GetAtt(EC2Instance1, "PrivateIp"),
    ),
    Output(
        "PublicDNS",
        Description="Public DNSName of Elastic Load Balancer",
        Value=GetAtt(ELB, "DNSName"),
    )
])

print(t.to_json())
