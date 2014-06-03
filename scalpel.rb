###
#
# Tools for dissector
#
###

require 'hex_string'
require 'digest'
require 'metasm'
require 'exifr'
#require 'virustotal'
require 'json'
require 'rest-client'
require 'mechanize'
require 'colorize'


class Analysis
  def identify(file)
    begin
      sample = File.open(file, "r")
    rescue
      puts "\n[!] Error accessing #{file}. Terminating..".red
      exit
    end
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
      puts "\n[!] Filetype: #{type} Analysis cannot complete.".red
      exit(0)
    end
    print "\n[+]".green
    puts " Filetype: #{type}"
    sample.close
    return type
  end

  def hashes(contents)
    sha256hash = Digest::SHA256.hexdigest contents
    sha1hash = Digest::SHA1.hexdigest contents
    md5hash = Digest::MD5.hexdigest contents
    puts "[*]".yellow
    puts "SHA256: #{sha256hash}"
    puts "SHA1: #{sha1hash}"
    puts "MD5: #{md5hash}"
    return sha1hash
  end

  def scan_pe(sample)
    hashes(sample)
    pe = Metasm::PE.decode_file_header(sample)
    puts "[*] PE Header Contents:\n#{pe.decode_header}".yellow
    vt_query(sample, sha2)
  end

  def scan_jpg(sample)
    hash = hashes(sample)
    img = EXIFR::JPEG.new(sample)

    puts "\nTime the image was captured: ".yellow
    if img.date_time != nil
      puts "#{img.date_time}".yellow
    else
      puts '[!] No Timestamp available'.red
    end

    meta = img.exif_data
    puts "\nExif data: ".yellow
    if img.exif? == 'True'
      puts "#{meta}".yellow
    else
      puts '[!] No Exif data available'.red
    end
    vt_query(sample, hash)
  end

  def scan_elf(sample)
    hash = hashes(sample)
    elf = Metasm::ELF.decode_file(sample)
    vt_query(sample, hash)
  end

  def scan_script(file)
    hash = hashes(file)
    sample = File.open(file, 'r')
    contents = sample.readlines.first.chomp
    print "\n[*] Interpreter: ".yellow
    puts contents
    vt_query(file, hash)
  end

  def vt_query(file, hash)
    apikey = '83c3e67223487e96428598086ffd7582679024acf45a361a15896bf1edafcc7c'
    contents = File.read(file)
    agent = Mechanize.new

    puts "\n[*] Searching file on VirusTotal...".yellow

    vtrequest = agent.post("https://www.virustotal.com/vtapi/v2/file/report", {
        "resource" => "#{hash}",
        "apikey" => "#{apikey}"
    })
    sleep(5)
    puts vtrequest.body

  end
end

