# VirusTotal module

require 'json'
require 'rest-client'
require 'colorize'

class VT
  def vtquery(file, hash)
    @sample_name = File.basename("#{file}")  
    if File.zero?('bin/vt.key')
      print "\n[!]".red
      print " Please place VisusTotal API key in bin/vt.key\n"
      exit(0)
    else
      apikey = File.read('bin/vt.key').chomp
    end

    begin
      vtrequest = RestClient.post "https://www.virustotal.com/vtapi/v2/file/report", :resource => "#{hash}", :apikey => "#{apikey}"
      sleep(5)
    rescue
      puts "\n[-] Could not connect to VirusTotal's database.. Check network connection.".red
      return
    end

    results = JSON.parse(vtrequest.body)
    vt_link = results["permalink"]

    if vt_link.nil?
      File.open("reports/#{@sample_name}.txt", "a") do |f1| f1.write("\n[-] File not found in VT database") end
    else
      total = results["total"]
      detected = results["positives"]
      File.open("reports/#{@sample_name}.txt", "a") do |f1| f1.write("\n[+] Link: #{vt_link}") end
      File.open("reports/#{@sample_name}.txt", "a") do |f1| f1.write("\n[+] Detection Ratio: #{detected}/#{total}") end
    end
  end  
end
