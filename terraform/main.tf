data "ec_stack" "latest" {
  version_regex = "latest"
  region        = var.region
}

resource "ec_deployment" "main" {
  name                   = var.deployment_name
  region                 = var.region
  version                = data.ec_stack.latest.version
  deployment_template_id = var.deployment_template_id

  elasticsearch = {
    hot = {
      size       = var.elasticsearch_size
      zone_count = var.elasticsearch_zone_count
      autoscaling = {}
    }
  }

  kibana = {
    topology = [{
      size       = var.kibana_size
      zone_count = var.kibana_zone_count
    }]
  }

  integrations_server = {}
}

# Workaround: elasticstack_kibana_space cannot manage the pre-existing "default"
# space (409 on create, 400 on destroy). Using local-exec with PUT instead.
# See: https://github.com/elastic/terraform-provider-elasticstack/issues/XXXX
resource "terraform_data" "kibana_default_space_security" {
  depends_on = [ec_deployment.main]

  input = {
    kibana_endpoint = ec_deployment.main.kibana.https_endpoint
    username        = ec_deployment.main.elasticsearch_username
    password        = ec_deployment.main.elasticsearch_password
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -s -X PUT \
        "${self.input.kibana_endpoint}/api/spaces/space/default" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -u "${self.input.username}:${self.input.password}" \
        -d '{"id":"default","name":"Default","description":"This is your default space!","solution":"security"}'
    EOT
  }
}
