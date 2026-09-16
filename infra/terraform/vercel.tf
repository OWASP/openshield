resource "vercel_project" "dashboard" {
  name           = "openshield-dashboard"
  framework      = "vite"
  root_directory = "frontend"

  git_repository = {
    type = "github"
    repo = "openshield-org/openshield"
  }

  environment = [
    {
      key       = "VITE_API_URL"
      value     = "https://openshield-api.onrender.com"
      target    = ["production", "preview"]
      sensitive = false
    }
  ]
}

resource "vercel_project" "website" {
  name           = "openshield-website"
  root_directory = "website"

  git_repository = {
    type = "github"
    repo = "openshield-org/openshield"
  }
}
