#!/usr/bin/ruby
##
#
# Tool for initial malware triage
# Developer: Y0xda
#
##

####################### Required #############################

# Dependency check
begin
  gem "bundler"
rescue LoadError
  system("gem install bundler")
  Gem.clear_paths
end

require 'rubygems'
require 'bundler/setup'
require 'trollop'
load 'bin/modules.rb'

# Declare CLI arguments
opts = Trollop::options do
  opt :file, "File to analyze", :type => :string
  opt :dir, "Toggle iterative directory analysis", :default => false
end


####################### Main Functions ###############################


def dirid(folder)
  # Identify given folder and test if it exists
  if Dir.exists?(folder)
    print "[*]".yellow
    puts " Recursively scanning #{folder}"
    items = Dir["#{folder}*"]
    @files = items
  else
    print "[!]".red
    puts " Could not access #{folder}"
    exit
  end
end


# Initializes analysis of files based on filetype
def analysis_init(type, malz)
  banner = "\n========== Analyzing #{type} =========="
  puts banner.yellow
  File.open("reports/#{malz}.txt", "w+") do |f1| f1.write("#{banner}") end

  case type
    when "PE"
      @analyze.scan_pe(malz)
    when "JPG"
      @analyze.scan_jpg(malz)
    when "ELF"
      @analyze.scan_elf(malz)
    when "Script"
      @analyze.scan_script(malz)
    when "PDF"
      @analyze.scan_pdf(malz)
    else
      puts "[!] Analysis cannot complete. Filetype unknown.".red
  end
  File.open("reports/#{malz}.txt", "a") do |f1| f1.write("\n[+] Analysis complete!\n") end
end

######################### ARG Parsing #########################


# Initialize Analysis
@analyze = Analysis.new

# Parses CLI arguments
if opts[:dir]
  folder = opts[:file]
  dirid(folder)
  @files.each do |file|
    if File.directory?(file)
      print "[*]".yellow
      puts " #{file} is a directory.. Skipped!"
    else
      ftype = @analyze.identify(file)
      scanthr = Thread.new { analysis_init(ftype, file) }
      scanthr.join
      while scanthr.alive? do
        @analyze.progress(file)
      end
    end
  end
elsif opts[:file_given]
  file = opts[:file]
  ftype = @analyze.identify(file)
  scanthr = Thread.new { analysis_init(ftype, file) }
  while scanthr.alive? do
    data = %w[ - \\ | / - \\ | / ]
    data.each { |s|
      sleep(0.2)
      print "\r[%s] Analyzing #{file}" % s
      }
      print
    end
    puts "\r[+] Finished analyzing #{file}!"
  print "\n[*]".green
  puts " Check reports/#{file}.txt for analysis details"
else  
  help = Trollop::Parser.new
  help.parse(opts)
  help.educate
  exit
end
  
