require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name         = "ExpoVpnSdk"
  s.version      = package['version']
  s.summary      = package['description']
  s.license      = package['license']
  s.authors      = package['author']
  s.homepage     = package['repository']['url']
  # DCAppAttestService (App Attest) requires iOS 14.
  s.platform     = :ios, "14.0"
  s.source       = { :git => package['repository']['url'], :tag => "v#{s.version}" }
  s.source_files = "*.{h,m,swift}"
  s.requires_arc = true
  s.frameworks   = "DeviceCheck"

  s.dependency "React-Core"
end