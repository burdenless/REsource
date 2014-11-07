# VirusTotal module

require 'mechanize'
require 'json'
require 'rest-client'
require 'colorize'

class VT
  def vtquery(file, hash)
    if File.exists?('bin/vt.key')
      apikey = File.read('bin/vt.key').chomp
    else
      print "\n[!]".red
      print " Please provide VisusTotal API key\n> "
      apikey = gets.chomp
    end
    contents = File.read(file)
    agent = Mechanize.new

    begin
      vtrequest = agent.post("https://www.virustotal.com/vtapi/v2/file/report", {
          "resource" => "#{hash}",
          "apikey" => "#{apikey}"
      })
      sleep(5)
    rescue
      puts "[-] Could not connect to VirusTotal's database.. Check network connection.".red
      exit(0)
    end

    results = JSON.parse(vtrequest.body)
    vt_link = results["permalink"]

    if vt_link.nil?
      File.open("reports/#{file}.txt", "a") do |f1| f1.write("\n[-] File not found in VT database") end
    else
      total = results["total"]
      detected = results["positives"]
      File.open("reports/#{file}.txt", "a") do |f1| f1.write("\n[+] Link: #{vt_link}") end
      File.open("reports/#{file}.txt", "a") do |f1| f1.write("\n[+] Detection Ratio: #{detected}/#{total}") end
    end
  end  
end
