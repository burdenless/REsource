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
load 'iter.rb'

# Declare CLI arguments
opts = Trollop::options do
  opt :file, "File to analyze", :type => :string
  opt :recurse, "Toggle recursive analysis on a folder", :default => false
end

# Initializes analysis of files based on filetype
def analysis_init(type)
  banner = "\n========== Analyzing #{type} =========="
  puts banner.yellow

  case type
    when "PE"
      @analyze.scan_pe(@file)
    when "JPG"
      @analyze.scan_jpg(@file)
    when "ELF"
      @analyze.scan_elf(@file)
    when "Script"
      @analyze.scan_script(@file)
    else
      puts "[!] Analysis cannot complete. Filetype unknown.".red
  end

  print "\n[+]".green
  puts " Analysis complete!"
end

# Parses CLI arguments
if opts[:recurse]
  puts "DEV NOTE: recursive scanning is in beta".yellow
  folder = opts[:file]
  recurse = Recurse.new
  recurse.dirid(folder)
elsif opts[:file_given]
  @file = opts[:file]
  print "\n[*]".yellow
  puts " Analyzing #{@file}"
  @analyze = Analysis.new
  ftype = @analyze.identify(@file)
  analysis_init(ftype)
else  
  help = Trollop::Parser.new
  help.parse(opts)
  help.educate
  exit
end
