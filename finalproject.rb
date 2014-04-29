#!/usr/bin/ruby
#
# Developed by Bobby Argenbright
#
# NTS370 - Final Project
# University of Advancing Technology
#
# Purpose: Identify & gather basic static information of files
#          Currently detects PE, ELF, JPG, and Scripts
#

begin
  gem "bundler"
rescue LoadError
  system("gem install bundler")
  Gem.clear_paths
end

require 'rubygems'
require 'bundler/setup'

require 'hex_string'
require 'digest'
require 'metasm'
require 'exifr'
#require 'virustotal'
require 'json'
require 'rest-client'
require 'mechanize'
require 'colorize'

puts '[?] File to analyze:'.cyan
print '> '.cyan
file = gets.chomp


class Analysis
  def identify(file)
    sample = File.open(file, "r")
    contents = sample.read
    hex = contents.to_hex_string
    magic = hex[0,5]
    if magic == "4d 5a"
      type = "PE"
    elsif magic == "ff d8"
      type = "JPG"
    elsif magic == "7f 45"
      type = "ELF"
    elsif magic == "23 21"
      type = "Script"
    else
      type = "unknown!"
    end
    puts "\n[+] Filetype: #{type}".green
    return type
  end

  def hashes(contents)
    sha1hash = Digest::SHA1.hexdigest contents
    puts "[*] SHA1 Digest: #{sha1hash}".yellow
    return sha1hash
  end

  def scan_pe(sample)
    hashes(sample)
    pe = Metasm::PE.decode_file_header(sample)
    puts "[*] PE Header Contents:\n#{pe.decode_header}".yellow
    vt_query(sample, sha2)
  end

  def scan_jpg(sample)
    hashes(sample)
    img = EXIFR::JPEG.new(sample)

    puts "\nTime the image was captured: "
    if img.date_time != nil
      puts "#{img.date_time}"
    else
      puts '[!] No Timestamp available'.red
    end

    meta = img.exif_data
    puts "\nExif data: "
    if img.exif? == 'True'
      puts "#{meta}"
    else
      puts '[!] No Exif data available'.red
    end
    vt_query(sample, sha2)
  end

  def scan_elf(sample)
    hash = hashes(sample)
    elf = Metasm::ELF.decode_file(sample)
    vt_query(sample, hash)
  end

  def scan_script(file)
    hashes(file)
    sample = File.open(file, 'r')
    contents = sample.read
    interp = contents[2,12]
    puts "\n[*] Interpreter: #{interp}".yellow
    vt_query(file, sha2)
  end

  def vt_query(file, sha2)
    apikey = '83c3e67223487e96428598086ffd7582679024acf45a361a15896bf1edafcc7c'
    contents = File.read(file)
    agent = Mechanize.new

    puts "\n[*] Searching file on VirusTotal...".yellow

    vtrequest = agent.post("https://www.virustotal.com/vtapi/v2/file/report", {
        "resource" => "#{sha2}",
        "apikey" => "#{apikey}"
    })
    sleep(5)
    puts vtrequest.body.yellow

  end
end

analyze = Analysis.new
type = analyze.identify(file)
banner = "\n========== Analyzing #{type} ==========\n"
puts banner.yellow

case type
  when "PE"
    analyze.scan_pe(file)
  when "JPG"
    analyze.scan_jpg(file)
  when "ELF"
    analyze.scan_elf(file)
  when "Script"
    analyze.scan_script(file)
  else
    puts "[!] Analysis cannot complete. Filetype unknown. Exiting...".red
end
