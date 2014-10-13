##
#
# Iterates analysis over a given directory and saves to an HTML report
#
##

require 'markaby'
load 'scalpel.rb'

class Recurse
  def dirid(folder)
    # Identify given folder and test if it exists
    if Dir.exists?(folder)
      print "[*]".yellow
      puts " Recursively scanning #{folder}"
      items = Dir["#{folder}*"]
      scan_all(items)
      exit
    else
      print "[!]".red
      puts " Could not access #{folder}"
      exit
    end
  end

  def scan_all(files)
    # Iterates over items in the given folder and scans them using the Analysis class
    files.each do |i|
      puts "#{i}"
    end
  end

  def reporting
    # Generate HTML reports with Markaby
  end
end