### PEdump Module

require 'pedump'
require 'json/add/struct'

def pedumper(fi)
        name = File.basename(fi)
	fi = File.open(fi.chomp)
        pe = PEdump.new
	

	### Get Compiler
	begin
		data = pe.packer(fi)
		packban = <<-packban

+-----------------+
| Packer/Compiler |
+-----------------+
packban
		File.open("reports/#{name}.txt", "a") do |f1| f1.write(packban) end

		File.open("reports/#{name}.txt", "a") do |f1| f1.write(data[0]['packer']['name'] + "\n") end
	rescue
		File.open("reports/#{name}.txt", "a") do |f1| f1.write("Error. Could not get compiler/packer information.") end
	end

	### Parse Sections ###
	begin
		data = pe.sections(fi)
		sections = data.to_json
		parsed = JSON.parse(sections, :create_additions => true)
                secban = <<-secban

+-----------------+
|    Sections     |
+-----------------+
secban
		File.open("reports/#{name}.txt", "a") do |f1| f1.write(secban) end
		File.open("reports/#{name}.txt", "a") do |f1| f1.write("Name\tVirtualSize\tVirtualAddress\tSizeOfRawData\tPointerToRawData\n") end
		count = 0
		output = ''
		while count < parsed.length
			par = parsed[count]
			output += "#{par['Name']}\t#{par['VirtualSize']}\t\t#{par['VirtualAddress']}\t\t#{par['SizeOfRawData']}\t\t#{par['PointerToRawData']}\n"
			count += 1
		end
	rescue
		output = 'Error. Could not parse Sections'
	end
	File.open("reports/#{name}.txt", "a") do |f1| f1.write(output) end

	### Get Imports ###

        iatban = <<-iatban

+----------------+
|    Imports     |
+----------------+
iatban
	begin
		File.open("reports/#{name}.txt", "a") do |f1| f1.write(iatban) end
		output = ''
		data = pe.imports(fi)		
		imports = data.to_json
                parsed = JSON.parse(imports, :create_additions => true)
                count = 0
		parcount = 3
                while count < parsed.length
                        par = parsed[count]
                        count += 1
			output += "\n#{par['module_name']}\n============\n"
			imports = par[6]
			while parcount < par.length
				output += "#{imports[parcount]['name']}\n"
				parcount += 1
			end
			parcount = 0
	  	end
	rescue
		print '[-]'.red
		puts ' Error during IAT parsing'
	end

	File.open("reports/#{name}.txt", "a") do |f1| f1.write(output) end	

end



