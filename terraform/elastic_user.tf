# --------------------------------------------------------------------------
# Cases viewer role and user for the SIEM demo
# --------------------------------------------------------------------------

resource "elasticstack_elasticsearch_security_role" "cases_viewer" {
  name = "cases_viewer"

  applications {
    application = "kibana-.kibana"
    privileges  = ["feature_securitySolutionCases.read"]
    resources   = ["space:default"]
  }
}

resource "elasticstack_elasticsearch_security_user" "ronny" {
  username  = "ronny_arbetsflode"
  full_name = "Ronny Arbetsflöde"
  roles     = [elasticstack_elasticsearch_security_role.cases_viewer.name]
  password  = var.cases_user_password

  depends_on = [elasticstack_elasticsearch_security_role.cases_viewer]
}
