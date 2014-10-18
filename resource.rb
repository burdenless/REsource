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
load 'modules.rb'

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
  print "\n[*]".yellow
  puts " Analyzing #{malz}"
  
  banner = "\n========== Analyzing #{type} =========="
  puts banner.yellow

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

  print "\n[+]".green
  puts " Analysis complete!"
end


######################### ARG Parsing #########################


# Initialize Analysis
@analyze = Analysis.new

# Parses CLI arguments
if opts[:dir]
  folder = opts[:file]
  #recurse = Recurse.new
  dirid(folder)
  @files.each do |file|
    if File.directory?(file)
	print "[*]".yellow
	puts " #{file} is a directory.. Skipped!"
    else
    	ftype = @analyze.identify(file)
    	analysis_init(ftype, file)
    end
  end
elsif opts[:file_given]
  file = opts[:file]
  ftype = @analyze.identify(file)
  analysis_init(ftype, file)
else  
  help = Trollop::Parser.new
  help.parse(opts)
  help.educate
  exit
end
  
