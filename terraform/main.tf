data "ec_stack" "latest" {
  version_regex = "9\\.3\\.4"
  region        = var.region
}

resource "ec_deployment" "main" {
  name                   = var.deployment_name
  region                 = var.region
  version                = data.ec_stack.latest.version
  deployment_template_id = var.deployment_template_id

  elasticsearch = {
    hot = {
      size        = var.elasticsearch_size
      zone_count  = var.elasticsearch_zone_count
      autoscaling = {}
    }
    ml = {
      size        = var.ml_size
      zone_count  = var.ml_zone_count
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
      # Write credentials to temp file (keeps them out of process table)
      CURL_AUTH=$(mktemp) && chmod 600 "$CURL_AUTH"
      printf 'user = "%s:%s"\n' "${self.input.username}" "${self.input.password}" > "$CURL_AUTH"

      curl -s -X PUT \
        "${self.input.kibana_endpoint}/api/spaces/space/default" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -K "$CURL_AUTH" \
        -d '{"id":"default","name":"Default","description":"This is your default space!","solution":"security"}'

      # Enable Elastic Workflows UI (the /api/kibana/settings endpoint is blocked
      # in Security solution view, so we set it via the config saved object directly)
      KIBANA_VERSION=$(curl -s "${self.input.kibana_endpoint}/api/status" \
        -K "$CURL_AUTH" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['version']['number'])")

      curl -s -X PUT \
        "${self.input.kibana_endpoint}/api/saved_objects/config/$${KIBANA_VERSION}" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -K "$CURL_AUTH" \
        -d '{"attributes":{"workflows:ui:enabled":true}}'

      rm -f "$CURL_AUTH"
    EOT
  }
}
