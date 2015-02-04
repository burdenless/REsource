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

# Display banner
puts <<Banner.green
 _ __ ___   ___  ___  _   _ _ __ ___ ___
| '__/ _ \\ / __|/ _ \\| | | | '__/ __/ _ \\
| |_|  __/_\\__ \\ (_) | |_| | | | (_|  __/
|_(_)\\___(_)___/\\___/ \\__,_|_|  \\___\\___|
Banner


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
  banner = <<-banner
+==== Analyzing #{type} ====+
banner
  puts banner.yellow
  @filename = File.basename(malz)  
  File.open("reports/#{@filename}.txt", "w+") do |f1| f1.write("#{banner}") end

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
  File.open("reports/#{@filename}.txt", "a") do |f1| f1.write("\n[+] Analysis complete!\n") end
end

######################### ARG Parsing #########################


# Initialize Analysis
@analyze = Analysis.new

# Parse CLI arguments
if opts[:dir]
  folder = opts[:file]
  dirid(folder)
  @files.each do |file|
    if File.directory?(file)
      print "[*]".yellow
      puts " #{file} is a directory.. Skipped!"
    else
      ftype = @analyze.identify(file)
      scanthr = Thread.new{analysis_init(ftype, file)}
      while scanthr.alive? do
        #@analyze.progress(file)  -- Future modularization of progress tracking
	data = %w[ - \\ | / - \\ | / ]
    	data.each { |s|
      	sleep(0.2)
      	print "\r[%s] Analyzing #{file}" % s
      	}
      end
      puts "\r[+] Finished analyzing #{file}!"
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
      print "\r[%s] Analyzing #{@filename}" % s
      }
      print
    end
    puts "\r[+] Finished analyzing #{@filename}!"
  print "\n[*]".green
  puts " Check reports/#{@filename}.txt for analysis details"
else  
  help = Trollop::Parser.new
  help.parse(opts)
  help.educate
  exit
end
  
