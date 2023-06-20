terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIATMXIUDIT63OVJS2P"
  secret_key = "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"
}

# Creating VPC
resource "aws_vpc" "Web_env" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "Web env"
  }
}


# Creating Internet gateway and attaching to vpc
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.Web_env.id

  tags = {
    Name = "My-IGW"
  }
}


# Creating Subnet

# Public subnet 1
resource "aws_subnet" "Public-1" {
  vpc_id                  = aws_vpc.Web_env.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = {
    Name = "Public-1"
  }
}

# Public subnet 2
resource "aws_subnet" "Public-2" {
  vpc_id                  = aws_vpc.Web_env.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1b"

  tags = {
    Name = "Public-2"
  }
}

# Public subnet 3
resource "aws_subnet" "Public-3" {
  vpc_id                  = aws_vpc.Web_env.id
  cidr_block              = "10.0.3.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1c"

  tags = {
    Name = "Public-3"
  }
}

# Private subnet 1
resource "aws_subnet" "Private-1" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.4.0/24"
  availability_zone       = "us-east-1a"

  tags = {
    Name = "Private-1"
  }
}

# Private subnet 2
resource "aws_subnet" "Private-2" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.5.0/24"
  availability_zone       = "us-east-1b"

  tags = {
    Name = "Private-2"
  }
}

# Private subnet 3
resource "aws_subnet" "Private-3" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.6.0/24"
  availability_zone       = "us-east-1c"

  tags = {
    Name = "Private-3"
  }
}

# Private subnet 4
resource "aws_subnet" "Private-4" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.7.0/24"
  availability_zone       = "us-east-1d"

  tags = {
    Name = "Private-4"
  }
}

# Private subnet 5
resource "aws_subnet" "Private-5" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.8.0/24"
  availability_zone       = "us-east-1e"

  tags = {
    Name = "Private-5"
  }
}

# Private subnet 6
resource "aws_subnet" "Private-6" {
  vpc_id     = aws_vpc.Web_env.id
  cidr_block = "10.0.9.0/24"
  availability_zone       = "us-east-1f"

  tags = {
    Name = "Private-6"
  }
}

# Creating Public Route Table
resource "aws_route_table" "Public_RT" {
  vpc_id = aws_vpc.Web_env.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "Public_RT"
  }
}

# Associating public route table w/ public subnets
# Public-1
resource "aws_route_table_association" "Public_RT-Public-1" {
  subnet_id      = aws_subnet.Public-1.id
  route_table_id = aws_route_table.Public_RT.id
}

# Public-2
resource "aws_route_table_association" "Public_RT-Public-2" {
  subnet_id      = aws_subnet.Public-2.id
  route_table_id = aws_route_table.Public_RT.id
}

# Public-3
resource "aws_route_table_association" "Public_RT-Public-3" {
  subnet_id      = aws_subnet.Public-3.id
  route_table_id = aws_route_table.Public_RT.id
}


# Generating ellastic ip for NAT
resource "aws_eip" "nat_allocated_ip" {
  vpc = true
}


# Create NAT gateway
resource "aws_nat_gateway" "My-NAT-gw" {
  allocation_id = aws_eip.nat_allocated_ip.id
  subnet_id     = aws_subnet.Public-1.id

  tags = {
    Name = "NAT gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}


# Creating Private Route Table
resource "aws_route_table" "Private_RT" {
  vpc_id = aws_vpc.Web_env.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.My-NAT-gw.id
  }

  tags = {
    Name = "Private_RT"
  }
}

# Private-1
resource "aws_route_table_association" "Private_RT-Private-1" {
  subnet_id      = aws_subnet.Private-1.id
  route_table_id = aws_route_table.Private_RT.id
}

# Private-2
resource "aws_route_table_association" "Private_RT-Private-2" {
  subnet_id      = aws_subnet.Private-2.id
  route_table_id = aws_route_table.Private_RT.id
}

# Private-3
resource "aws_route_table_association" "Private_RT-Private-3" {
  subnet_id      = aws_subnet.Private-3.id
  route_table_id = aws_route_table.Private_RT.id
}

# Private-4
resource "aws_route_table_association" "Private_RT-Private-4" {
  subnet_id      = aws_subnet.Private-4.id
  route_table_id = aws_route_table.Private_RT.id
}

# Private-5
resource "aws_route_table_association" "Private_RT-Private-5" {
  subnet_id      = aws_subnet.Private-5.id
  route_table_id = aws_route_table.Private_RT.id
}

# Private-6
resource "aws_route_table_association" "Private_RT-Private-6" {
  subnet_id      = aws_subnet.Private-6.id
  route_table_id = aws_route_table.Private_RT.id
}



# Fetching AMMI for an ec2 instance
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}


# Creating Security Group for webservs
resource "aws_security_group" "web_server_sg" {
  name        = "web_server"
  description = "Allows HTTP and HTTPS connection"
  vpc_id      = aws_vpc.Web_env.id

  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_http&https"
  }
}

# Creating Security Group for webservs for SSH
resource "aws_security_group" "web_server_ssh_sg" {
  name        = "ssh_sg"
  description = "Allows SSH"
  vpc_id      = aws_vpc.Web_env.id

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh"
  }
}

# Creating Security Group for webservs for ICMP
resource "aws_security_group" "web_server_ping_sg" {
  name        = "icmp_sg"
  description = "Allows ICMP"
  vpc_id      = aws_vpc.Web_env.id

  ingress {
    description = "Allow all incoming ICMP IPv4 traffic"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all incoming ICMP IPv4 traffic"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ping"
  }
}

# Creating Security Group for webservs for EFS
resource "aws_security_group" "web_server_efs_sg" {
  name        = "efs_sg"
  description = "Allows ICMP"
  vpc_id      = aws_vpc.Web_env.id

  ingress {
    description = "EFS mount target"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_efs_mount"
  }
}


#Resource to create a SSH private key
resource "tls_private_key" "my_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Key pair
resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = tls_private_key.my_key.public_key_openssh

  # Create a "myKey.pem" to your computer
  provisioner "local-exec" {
    command = "echo '${tls_private_key.my_key.private_key_pem}' > ./deployer-key.pem"
  }
}


# Deploying Public webserver in Public-1 subnet
resource "aws_instance" "web-server-1" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  subnet_id       = aws_subnet.Public-1.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]

  key_name = aws_key_pair.deployer.key_name

  user_data = <<-EOF
  #!/bin/bash -ex
  
  sudo apt install apache2 -y
  sudo systemctl start apache2
  cd /var/www/html
  echo "<h1>This is server 1.</h1>" > index.html
  sudo systemctl restart apache2
  EOF

  tags = {
    Name = "Web-server-1"
  }
}


# Deploying Public webserver in Public-2 subnet
resource "aws_instance" "web-server-2" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  subnet_id       = aws_subnet.Public-2.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]

  key_name = aws_key_pair.deployer.key_name

  user_data = <<-EOF
  #!/bin/bash -ex
  
  sudo apt install apache2 -y
  sudo systemctl start apache2
  cd /var/www/html
  echo "<h1>This is server 2.</h1>" > index.html
  sudo systemctl restart apache2
  EOF

  tags = {
    Name = "Web-server-2"
  }
}


# Deploying Public webserver in Public-3 subnet
resource "aws_instance" "web-server-3" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  subnet_id       = aws_subnet.Public-3.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]

  key_name = aws_key_pair.deployer.key_name

  user_data = <<-EOF
  #!/bin/bash -ex
  
  sudo apt install apache2 -y
  sudo systemctl start apache2
  cd /var/www/html
  echo "<h1>This is server 3.</h1>" > index.html
  sudo systemctl restart apache2
  EOF

  tags = {
    Name = "Web-server-3"
  }
}

# Creating application load balancer
resource "aws_lb" "appl_elb" {
  name               = "test-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web_server_sg.id]
  subnets            = [aws_subnet.Public-1.id, aws_subnet.Public-2.id, aws_subnet.Public-3.id]

  enable_deletion_protection = true

  # access_logs {
  #   bucket  = aws_s3_bucket.lb_logs.id
  #   prefix  = "test-lb"
  #   enabled = true
  # }

  tags = {
    Environment = "appl-lb"
  }
}

# Creating target group
resource "aws_lb_target_group" "elb_tg" {
  name     = "elb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.Web_env.id
}


# Attaching ec2 instrances to ec2
resource "aws_lb_target_group_attachment" "target-1" {
  target_group_arn = aws_lb_target_group.elb_tg.arn
  target_id        = aws_instance.web-server-1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "target-2" {
  target_group_arn = aws_lb_target_group.elb_tg.arn
  target_id        = aws_instance.web-server-2.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "target-3" {
  target_group_arn = aws_lb_target_group.elb_tg.arn
  target_id        = aws_instance.web-server-3.id
  port             = 80
}


# adding listner
resource "aws_lb_listener" "elb_listner" {
  load_balancer_arn = aws_lb.appl_elb.arn
  port              = "80"
  protocol          = "HTTP"
  # ssl_policy        = "ELBSecurityPolicy-2016-08"
  # certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.elb_tg.arn
  }
}

# Creating EFS Volume
resource "aws_efs_file_system" "my-efs" {
  creation_token = "my-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  tags = {
    Name = "My-efs"
  }
}


# Creating mount target
resource "aws_efs_mount_target" "efs_mount_1" {
  file_system_id  = aws_efs_file_system.my-efs.id
  subnet_id       = aws_subnet.Private-1.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]
}

# Creating mount target
resource "aws_efs_mount_target" "efs_mount_2" {
  file_system_id  = aws_efs_file_system.my-efs.id
  subnet_id       = aws_subnet.Private-2.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]
}

# Creating mount target
resource "aws_efs_mount_target" "efs_mount_3" {
  file_system_id  = aws_efs_file_system.my-efs.id
  subnet_id       = aws_subnet.Private-3.id
  security_groups = [aws_security_group.web_server_sg.id, aws_security_group.web_server_ssh_sg.id, aws_security_group.web_server_ping_sg.id, aws_security_group.web_server_efs_sg.id]
}

# # Creating Mount Point for EFS
# resource "null_resource" "configure_nfs_1" {
#   depends_on = [aws_efs_mount_target.efs_mount_1]
#   connection {
#     type     = "ssh"
#     user     = "ubuntu"
#     private_key = tls_private_key.my_key.private_key_pem
#     host     = aws_instance.web-server-1.public_ip
#   }

#   provisioner "remote-exec" {
#     inline = [
#       "sudo su",
#       "sudo apt-get update -y",
#       "sudo apt-get install nfs-common -y",
#       "nfsstat --version",
#       "nfsstat -m",
#       "sudo mkdir -p efs/",
#       "sudo mount -t nfs4 ${aws_efs_file_system.my-efs.dns_name}:/ efs"
#     ]
#   }
# }

# # Creating Mount Point for EFS
# resource "null_resource" "configure_nfs_2" {
#   depends_on = [aws_efs_mount_target.efs_mount_1]
#   connection {
#     type     = "ssh"
#     user     = "ubuntu"
#     private_key = tls_private_key.my_key.private_key_pem
#     host     = aws_instance.web-server-2.public_ip
#   }

#   provisioner "remote-exec" {
#     inline = [
#       "sudo su",
#       "apt-get update -y",
#       "apt-get install nfs-common -y",
#       "nfsstat --version",
#       "nfsstat -m",
#       "mkdir -p efs/",
#       "mount -t efs -o tls ${aws_efs_file_system.my-efs.dns_name}:/ efs"
#     ]
#   }
# }

# # Creating Mount Point for EFS
# resource "null_resource" "configure_nfs_3" {
#   depends_on = [aws_efs_mount_target.efs_mount_1]
#   connection {
#     type     = "ssh"
#     user     = "ubuntu"
#     private_key = tls_private_key.my_key.private_key_pem
#     host     = aws_instance.web-server-3.public_ip
#   }

#   provisioner "remote-exec" {
#     inline = [
#       "sudo su",
#       "apt-get update -y",
#       "apt-get install nfs-common -y",
#       "nfsstat --version",
#       "nfsstat -m",
#       "mkdir -p efs/",
#       "mount -t efs -o tls ${aws_efs_file_system.my-efs.dns_name}:/ efs"
#     ]
#   }
# }


# "sudo su"
# "apt-get update"
# "apt-get install nfs-common -y"
# "nfsstat --version"
# "nfsstat -m"
# "mkdir -p efs/"
# "mount -t nfs4 10.0.4.93:/ efs"




