#!/usr/bin/ruby
#
# Tool for initial malware triage
# developed by: Pendrak0n
#
##

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
load 'scalpel.rb'

# Declare CLI arguments
opts = Trollop::options do
  opt :file, "File to analyze", :type => :string
  opt :dir, "Toggle iterative directory analysis", :default => false
end

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
def analysis_init(type, filename)
  print "\n[*]".yellow
  puts " Analyzing #{filename}"
  
  banner = "\n========== Analyzing #{type} =========="
  puts banner.yellow

  case type
    when "PE"
      @analyze.scan_pe(filename)
    when "JPG"
      @analyze.scan_jpg(filename)
    when "ELF"
      @analyze.scan_elf(filename)
    when "Script"
      @analyze.scan_script(filename)
    else
      puts "[!] Analysis cannot complete. Filetype unknown.".red
  end

  print "\n[+]".green
  puts " Analysis complete!"
end

# Initialize Analysis
@analyze = Analysis.new

# Parses CLI arguments
if opts[:dir]
  puts "DEV NOTE: recursive scanning is in beta".yellow
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
