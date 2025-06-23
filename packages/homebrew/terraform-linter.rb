class TerraformLinter < Formula
  desc "A security-focused Terraform linter"
  homepage "https://github.com/heyimusa/go-terraform-linter"
  version "v1.0.0"
  url "https://github.com/heyimusa/go-terraform-linter/releases/download/v1.0.0/terraform-linter-$(uname -s | tr A-Z a-z)-$(uname -m).tar.gz"
  def install
    bin.install "terraform-linter"
  end
  test do
    assert_match version.to_s, shell_output("#{bin}/terraform-linter --version")
  end
end
