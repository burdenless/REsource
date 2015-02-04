### PEdump Module

require 'pedump'
require 'json/add/struct'

def pedumper(fi)
        fi = File.open(fi.chomp)
        pe = PEdump.new

	### Get Compiler
	begin
		data = pe.packer(fi)
		puts '==== Packer/Compiler ===='
		puts data[0]['packer']['name']
	rescue
		puts "Error. Could not get compiler/packer information."
	end

	### Parse IAT ###
	begin
		data = pe.sections(fi)
		iat = data.to_json
		parsed = JSON.parse(iat, :create_additions => true)
		puts "\n==== Sections ===="
		printf "Name\tVirtualSize\tVirtualAddress\tSizeOfRawData\tPointerToRawData\n"
		count = 0
		while count < parsed.length
			par = parsed[count]
			printf "#{par['Name']}\t#{par['VirtualSize']}\t\t#{par['VirtualAddress']}\t\t#{par['SizeOfRawData']}\t\t#{par['PointerToRawData']}\n"
			count += 1
		end
	rescue
		puts 'Error. Could not parse IAT'
	end
end



