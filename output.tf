# Outputs

output "internet_gateway_ip" {
  value = aws_internet_gateway.igw.id
}

output "nat_ip" {
  value = aws_eip.nat_allocated_ip.public_ip
}

output "subnet-public-1-ip" {
  value = aws_subnet.Public-1.id
}

output "subnet-public-2-ip" {
  value = aws_subnet.Public-2.id
}

output "subnet-public-3-ip" {
  value = aws_subnet.Public-3.id
}

output "subnet-private-1-ip" {
  value = aws_subnet.Private-1.id
}

output "subnet-private-2-ip" {
  value = aws_subnet.Private-2.id
}

output "subnet-private-3-ip" {
  value = aws_subnet.Private-3.id
}

output "subnet-private-4-ip" {
  value = aws_subnet.Private-4.id
}

output "subnet-private-5-ip" {
  value = aws_subnet.Private-5.id
}

output "subnet-private-6-ip" {
  value = aws_subnet.Private-6.id
}

output "ubuntu_ami" {
  value = data.aws_ami.ubuntu.id
}

output "public-1-subnet-ec2-ip" {
  value = aws_instance.web-server-1.public_ip
}

output "ssh_key" {
  value = tls_private_key.my_key.public_key_openssh
}

output "deployer" {
  value = aws_key_pair.deployer
}
