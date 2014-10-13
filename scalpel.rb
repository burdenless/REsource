###
#
# Tools for dissector
#
###

require 'hex_string'
require 'digest'
require 'metasm'
require 'exifr'
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
    @hex = contents.to_hex_string
    magic = @hex[0,5]
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
    puts " Filetype identified: #{type}"
    sample.close
    return type
  end

  def hashes(contents)
    sha256hash = Digest::SHA256.file(contents).hexdigest
    sha1hash = Digest::SHA1.file(contents).hexdigest
    md5hash = Digest::MD5.file(contents).hexdigest
    puts "\n[*] Hashes".yellow
    puts "SHA256: #{sha256hash}"
    puts "SHA1: #{sha1hash}"
    puts "MD5: #{md5hash}"
    return sha1hash
  end

  def scan_pe(sample)
    ## Hashes the sample ##
    hash = hashes(sample)

    ## Set Image File Header values ##
    win32 = "014c"
    itanium64 = "0200"
    winamd64 = "8664"

    ## Identify File Header relative to start of PE header ##
    offset = @hex.index "50 45 00 00"
    offset = offset + 12
    a = @hex[offset, 5]
    
    test32 = a.index('4c 01')
    testia64 = a.index('00 02')
    test64 = a.index ('86 64')
    if test32.nil?
      if testia64.nil?
        if test64.nil?
          build = "Unknown"
        else
          build = "AMD-64 (64-bit x64)"
	end
      else
        build = "IA-64 (Itanium)"
      end
    else
      build = "i386 (32-bit x86)"
    end

    puts "\n[*] File Architecture: ".yellow
    if build == "Unknown"
      print "[-]".red
      puts " #{build}"
    else
      print "[+]".green
      puts " #{build}"
    end

    ## Outputs strings from sample to a file
    strings(sample)

    ## Searches Virustotal for sample
    vt_query(sample, hash)


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
    ## Provide hashes
    hash = hashes(sample)

    elf = Metasm::ELF.decode_file(sample)

    ## Output strings to file
    strings(sample)

    ## Query VT for sample
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
    apikey = '' # VirusTotal API key goes here
    if apikey.empty?
      print "\n[!]".red
      print " Please provide VisusTotal API key\n> "
      apikey = gets.chomp
    else
    end
    contents = File.read(file)
    agent = Mechanize.new

    puts "\n[*] Searching VirusTotal for this sample...".yellow
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
      print "[-] ".red
      puts "File not found in VT database"
    else
      print "[+]".green
      puts " Link:"
      puts "#{vt_link}"
    end
  end

  def strings(sample)
    ## Writes file strings to a text file
    puts "\n[*] Acquiring strings..".yellow
    strings = `strings #{sample}`
    begin
      print "[+]".green
      puts " Output strings to #{sample}_strings.txt"
      File.open("#{sample}_strings.txt", 'w+') {|f| f.write(strings) }
    rescue
      print "[-]".red
      puts " Could not output strings to file."
    end
  end
end

