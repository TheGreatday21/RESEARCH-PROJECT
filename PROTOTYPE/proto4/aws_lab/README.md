# Optional AWS EC2 Throwaway Test Target (`aws_lab/`)

> **Test tooling, not part of LAPA.**
> LAPA itself never launches servers, installs software on targets, or sends HTTP traffic to real servers. The files in `aws_lab/` are standalone helper templates for anyone who wants to spin up a disposable EC2 test server manually and tear it down afterwards.

## Warning about public IP exposure

**Any EC2 instance with a public IP and port 80 open to `0.0.0.0/0` is scanned by automated internet bots within minutes.**

- Always restrict **SSH (TCP 22)** to your own workstation IP (`<YOUR_IP>/32`).
- For labelled evaluation runs against a throwaway instance, also restrict **HTTP (TCP 80)** to `<YOUR_IP>/32`. If you leave port 80 open to the internet, background scanner traffic will appear in `access.log` without `X-Lapa-Trace` headers; LAPA's evaluator reports unlabelled detections separately (`unlabelled_detections_count`, not counted as false positives), but restricting port 80 keeps test runs clean and predictable.

## 1. Create a restricted Security Group (read and run manually)

Replace `<YOUR_IP>` with your current public IPv4 address (for example `203.0.113.5`) and `<REGION>` with your chosen AWS region:

```sh
MY_IP="<YOUR_IP>/32"
REGION="eu-west-1"

SG_ID=$(aws ec2 create-security-group \
  --region "$REGION" \
  --group-name lapa-throwaway-test-sg \
  --description "LAPA throwaway test target (analyst IP only)" \
  --query GroupId --output text)

aws ec2 authorize-security-group-ingress --region "$REGION" \
  --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$MY_IP"

aws ec2 authorize-security-group-ingress --region "$REGION" \
  --group-id "$SG_ID" --protocol tcp --port 80 --cidr "$MY_IP"
```

## 2. Launch a throwaway EC2 instance with `user_data_bootstrap.sh`

Pick an Ubuntu 24.04 or Amazon Linux 2023 AMI ID for your region (`<AMI_ID>`) and an existing EC2 key pair name (`<KEY_PAIR_NAME>`). Notice `--metadata-options HttpTokens=required` enforces IMDSv2:

```sh
INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "<AMI_ID>" \
  --instance-type t3.micro \
  --key-name "<KEY_PAIR_NAME>" \
  --security-group-ids "$SG_ID" \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --user-data file://aws_lab/user_data_bootstrap.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lapa-throwaway-test}]' \
  --query 'Instances[0].InstanceId' --output text)

echo "Launched $INSTANCE_ID"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
PUBLIC_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Public IP: $PUBLIC_IP"
```

Wait roughly 30–60 seconds for cloud-init to finish installing nginx and updating group `adm`.

## 3. Optional: Send seeded test traffic from the command line

Sending test traffic to an EC2 server is strictly a command-line test action and is **never** wired into the LAPA GUI. If you want labelled synthetic requests on your throwaway instance:

```sh
.venv/bin/python -m lab.traffic.generate \
  --base-url "http://${PUBLIC_IP}" \
  --output aws_lab_labels.jsonl
```

You can then:

1. In the LAPA GUI, select **My server (AWS EC2)**, enter `$INSTANCE_ID`, `$PUBLIC_IP`, SSH user (`ubuntu` on Ubuntu, `ec2-user` on Amazon Linux), and your `.pem` key (`chmod 0600`).
2. Click **Check access** (runs read-only `lapa preflight`), then run **Acquire**, **Show manifest**, **Verify**, **Parse**, **Verify derived**, **Analyze**, and **Detect**.
3. On Page 3, expand **Advanced: ground-truth labels (testing only)** and pick `aws_lab_labels.jsonl` to run **Evaluate** and include the labelled scores in **Report**.

## 4. Teardown (always run when finished)

Terminate the throwaway instance and remove the temporary security group so you do not leave resources running:

```sh
aws ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID"
aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$INSTANCE_ID"
aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID"
```
