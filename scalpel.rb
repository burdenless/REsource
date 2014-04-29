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
    end
    puts "\n[+] Filetype: #{type}".green
    sample.close
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
    hash = hashes(file)
    sample = File.open(file, 'r')
    contents = sample.readlines.first.chomp
    puts "\n[*] Interpreter: #{contents}".yellow
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
    puts vtrequest.body.yellow

  end
end

