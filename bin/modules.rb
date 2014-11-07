###
#
# R.E.source Modules
#
###

require 'hex_string'
require 'digest'
require 'metasm'
require 'exifr'
require 'colorize'
require_relative 'vtquery'

VT = VT.new()

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
    elsif magic == "25 50"
      type = "PDF"
    else
      type = "unknown!"
      puts "\n[!] Filetype: #{type} Analysis cannot complete.".red
      exit(0)
    end
    sample.close
    return type
  end


######################### Hashing Module ########################


  def hashes(contents)
    sha256hash = Digest::SHA256.file(contents).hexdigest
    sha1hash = Digest::SHA1.file(contents).hexdigest
    md5hash = Digest::MD5.file(contents).hexdigest
    return sha256hash
  end


######################### PE Module ########################


  def scan_pe(sample)
    ## Analyzes PE Files

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

    File.open("reports/#{sample}.txt", "a") do |f1|  f1.write("\n[*] File Architecture: #{build}") end

    ## Outputs strings from sample to a file
    strings(sample)

    ## Searches Virustotal for sample
    VT::vtquery(sample, hash)
  end


######################### JPG Module ########################


  def scan_jpg(sample)
    ## Analyzes JPG files

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
    VT::vtquery(sample, hash)
  end


######################### Script Module ########################


  def scan_script(file)
    ## Analyzes Script files

    hash = hashes(file)
    sample = File.open(file, 'r')
    contents = sample.readlines.first.chomp
    print "\n[*] Interpreter: ".yellow
    puts contents
    VT::vtquery(file, hash)
  end


######################### Strings Module ########################


  def strings(sample)
    ## Writes file strings to a text file
    
    strings = `strings #{sample}`
    
    begin
      if Dir.exists?("strings") or Dir.exists?("../strings")
      else
	Dir.mkdir('strings')
      end
      Dir.chdir('strings')
      File.open("#{sample}_strings.txt", 'w+') {|f| f.write(strings)}
      Dir.chdir('../')
      File.open("reports/#{sample}.txt", "a") do |f1| f1.write("\n[*] Output strings to strings/#{sample}_strings.txt") end
    rescue
      print "[-]".red
      puts " Could not output strings to file."
    end
  end
end
