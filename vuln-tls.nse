local shortport = require("shortport")
local outlib = require("outlib")
local datetime = require("datetime")
local nmap = require("nmap")
local stdnse = require("stdnse")
local sslcert = require("sslcert")
local tls = require("tls")
local http = require("http")
local have_openssl, openssl = pcall(require, "openssl")

-- BASED ON:
-- 		https://github.com/nmap/nmap/blob/master/scripts/ssl-cert.nse  -> para obtener certificado los expire date, el autocifrado
-- 		client hello https://svn.nmap.org/nmap/scripts/tls-alpn.nse -> importante para protocolo (version TLS), compresor, cipher suites
--      ssl-enum-ciphers https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html -> to work with cipher suites

description = [[
	Crawls vulnerable HTTPS servers and checks for a number of SSL/TLS misconfigurations.
]]

categories = { "safe", "discovery", "vuln" }
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- @usage
-- nmap -p 80,443 --script vulnTLSServer <ip>
--
-- @output
-- **********************
-- CRITICAL ALERTS: 2
-- **********************
-- - Self-signed certificate detected
-- - Cipher includes CBC mode and SHA hash algorithm
-- **********************
-- HIGH ALERTS: 2
-- **********************
-- - Unsupported TLS cipher: TLS-RSA-WITH-AES-128-CBC-SHA
-- - Server does not support TLS 1.2 or TLS 1.3 by default
-- **********************
-- MEDIUM ALERTS: 1
-- **********************
-- - Certificate lifespan is 75 days (less than recommended 90 days)
-- **********************
--
portrule = shortport.ssl

local CHUNK_SIZE = 64
local tls13proto = tls.PROTOCOLS["TLSv1.3"]
local tls13supported = tls.EXTENSION_HELPERS.supported_versions({ "TLSv1.3" })

-- added safer cipher suites than the ones mentioned in the project doc
-- obtained from https://ciphersuite.info/cs/
local safeCipherSuites = { "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305",
	"ECDHE-RSA-CHACHA20-POLY1305", "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
	"DHE-RSA-CHACHA20-POLY1305", "TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_CCM_SHA256",
	"TLS_ECCPWD_WITH_AES_128_CCM_SHA256", "TLS_ECCPWD_WITH_AES_256_CCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	"TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
	"TLS_ECCPWD_WITH_AES_128_GCM_SHA256", "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", }


-- From ssl-cert.nse to store all fields in a table (for cert.subject or issuer for example)
local function name_to_table(name)
	local output = {}
	for k, v in pairs(name) do
		if type(k) == "table" then
			k = table.concat(k, ".")
		end
		output[k] = v
	end
	return outlib.sorted_by_key(output)
end

-- From ssl-cert.nse to format .getCertificate into normal key-value table
local function output_tab(cert)
	if not have_openssl then
		-- OpenSSL is required to parse the cert, so just dump the PEM
		return { pem = cert.pem }
	end
	local o = stdnse.output_table()
	o.subject = name_to_table(cert.subject)
	o.issuer = name_to_table(cert.issuer)

	o.pubkey = stdnse.output_table()
	o.pubkey.type = cert.pubkey.type
	o.pubkey.bits = cert.pubkey.bits

	if cert.pubkey.type == "rsa" then
		o.pubkey.modulus = openssl.bignum_bn2hex(cert.pubkey.modulus)
		o.pubkey.exponent = openssl.bignum_bn2dec(cert.pubkey.exponent)
	elseif cert.pubkey.type == "ec" then
		local params = stdnse.output_table()
		o.pubkey.ecdhparams = { curve_params = params }
		params.ec_curve_type = cert.pubkey.ecdhparams.curve_params.ec_curve_type
		params.curve = cert.pubkey.ecdhparams.curve_params.curve
	end

	if cert.extensions and #cert.extensions > 0 then
		o.extensions = {}
		for i, v in ipairs(cert.extensions) do
			local ext = stdnse.output_table()
			ext.name = v.name
			ext.value = v.value
			ext.critical = v.critical
			o.extensions[i] = ext
		end
	end
	o.sig_algo = cert.sig_algorithm

	o.validity = stdnse.output_table()
	for _, k in ipairs({ "notBefore", "notAfter" }) do
		local v = cert.validity[k]
		if type(v) == "string" then
			o.validity[k] = v
		else
			o.validity[k] = datetime.format_timestamp(v)
		end
	end
	o.md5 = stdnse.tohex(cert:digest("md5"))
	o.sha1 = stdnse.tohex(cert:digest("sha1"))
	o.pem = cert.pem
	return o
end

-- Auxiliary function to print table in order to see all fields from terminal
local function print_table(t, indent)
	indent = indent or ""
	for k, v in pairs(t) do
		if type(v) == "table" then
			print(indent .. tostring(k) .. ":")
			print_table(v, indent .. "  ")
		else
			print(indent .. tostring(k) .. ": " .. tostring(v))
		end
	end
end

-- From tls-alpn.nse to review answer from server
local function reviewServerHello(response)
	local resp = true
	stdnse.debug("reviewServerHello: Entering function to process server's response")
	local _, record = tls.record_read(response, 1)

	if record then
		stdnse.debug("[func:reviewServerHello]: Register read. Register type: %s", record.type)

		if record.type == "handshake" and record.body[1].type == "server_hello" then
			stdnse.debug("[func:reviewServerHello]: Response contains handshake with server_hello")
			-- print("\n\n--------------------SERVER HELLO CONTENT---------------------------")
			-- print_table(record.body[1], "\t") -- print table so we see all host values (to compare checks)
			-- print("\n--------------------------------------------------------------\n\n")
		else
			stdnse.debug(
				"[func:reviewServerHello]: The register doesn't contain the expected type 'handshake' or does not contain server_hello"
			)
			resp = false
		end
	end

	return resp, record
end

-- From tls-alpn.nse, send client hello handshake to server and start TLS connection
local function clientHello(host, port)
	local resp = true
	stdnse.debug("[func:clientHello]: Sending ClientHello message from %s:%d", host.ip, port.number)
	local cli_h = tls.client_hello({ protocol = "TLSv1.2" })

	local status, err, sock
	local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
	if specialized then
		status, sock = specialized(host, port)
	else
		sock = nmap.new_socket()
		status, err = sock:connect(host, port)
	end

	if not status then
		stdnse.debug("[func:ClientHello]: Error when connecing to server: %s", err or sock)
		resp = false
	end

	sock:set_timeout(5000)

	status, err = sock:send(cli_h)
	if not status then
		stdnse.debug("[func:ClientHello]: Couldn't send clientHello message: %s", err)
		sock:close()
		resp = false
	end

	local response
	status, response, err = tls.record_buffer(sock)
	if not status then
		stdnse.debug("Couldn't receive the answer: %s", err)
		sock:close()
		resp = false
	end

	sock:close()

	return resp, response
end

-- From ssl-enum-ciphers,  Get TLS extensions
local function base_extensions(host)
	local tlsname = tls.servername(host)
	return {
		-- Claim to support common elliptic curves
		["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](tls.DEFAULT_ELLIPTIC_CURVES),
		-- Some servers require Supported Point Formats Extension
		["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"]({ "uncompressed" }),
		-- Enable SNI if a server name is available
		["server_name"] = tlsname and tls.EXTENSION_HELPERS["server_name"](tlsname),
	}
end

-- From ssl-enum-ciphers, prepare hello table for server
local function get_hello_table(host, protocol)
	local t = {
		protocol = protocol,
		record_protocol = protocol, -- improve chances of immediate rejection
		extensions = base_extensions(host),
	}

	-- supported_versions extension required for TLSv1.3
	if (tls.PROTOCOLS[protocol] >= tls13proto) then
		t.extensions.supported_versions = tls13supported
	end

	return t
end

-- From ssl-enum-ciphers, sort keys
local function sorted_keys(t)
	local ret = {}
	for k, _ in pairs(t) do
		ret[#ret + 1] = k
	end
	table.sort(ret)
	return ret
end

-- From ssl-enum-ciphers, sort chunk of data
local function in_chunks(t, size)
	size = math.floor(size)
	if size < 1 then size = 1 end
	local ret = {}
	for i = 1, #t, size do
		local chunk = {}
		for j = i, i + size - 1 do
			chunk[#chunk + 1] = t[j]
		end
		ret[#ret + 1] = chunk
	end
	return ret
end
-- From ssl-enum-ciphers, get size of data
local function get_chunk_size(host, protocol)
	local len_t = get_hello_table(host, protocol)
	len_t.ciphers = {}
	local cipher_len_remaining = 255 - #tls.client_hello(len_t)
	-- if we're over 255 anyway, just go for it.
	-- Each cipher adds 2 bytes
	local max_chunks = cipher_len_remaining > 1 and cipher_len_remaining // 2 or CHUNK_SIZE
	-- otherwise, use the min
	return max_chunks < CHUNK_SIZE and max_chunks or CHUNK_SIZE
end

-- From ssl-enum-ciphers, returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
	local buffer = ""
	local i = 1
	local fragment
	return function()
		local record
		i, record = tls.record_read(buffer, i, fragment)
		if record == nil then
			local status, err
			status, buffer, err = tls.record_buffer(sock, buffer, i)
			if not status then
				return nil, err
			end
			i, record = tls.record_read(buffer, i, fragment)
			if record == nil then
				return nil, "done"
			end
		end
		fragment = record.fragment
		return record
	end
end

-- From ssl-enum-ciphers, try different parameters being sent to server
local function try_params(host, port, t)
	-- Use Nmap's own discovered timeout plus 5 seconds for host processing
	-- Default to 10 seconds total.
	local timeout = ((host.times and host.times.timeout) or 5) * 1000 + 5000

	-- Create socket.
	local status, sock, err
	local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
	if specialized then
		status, sock = specialized(host, port)
		if not status then
			stdnse.debug(1, t.protocol, "Can't connect: %s", sock)
			return nil
		end
	else
		sock = nmap.new_socket()
		sock:set_timeout(timeout)
		status, err = sock:connect(host, port)
		if not status then
			stdnse.debug(1, t.protocol, "Can't connect: %s", err)
			sock:close()
			return nil
		end
	end

	sock:set_timeout(timeout)

	-- Send request.
	local req = tls.client_hello(t)
	status, err = sock:send(req)
	if not status then
		stdnse.debug(1, t.protocol, "Can't send: %s", err)
		sock:close()
		return nil
	end

	-- Read response.
	local get_next_record = get_record_iter(sock)
	local records = {}
	while true do
		local record
		record, err = get_next_record()
		if not record then
			stdnse.debug(1, t.protocol, "Couldn't read a TLS record: %s", err)
			sock:close()
			return records
		end
		-- Collect message bodies into one record per type
		records[record.type] = records[record.type] or record
		local done = false
		for j = 1, #record.body do -- no ipairs because we append below
			local b = record.body[j]
			done = ((record.type == "alert" and b.level == "fatal") or
				(record.type == "handshake" and (b.type == "server_hello_done" or
					-- TLSv1.3 does not have server_hello_done
					(t.protocol == "TLSv1.3" and b.type == "server_hello")))
			)
			table.insert(records[record.type].body, b)
		end
		if done then
			sock:close()
			return records
		end
	end
end

-- From ssl-enum-ciphers, get a message body from a record which has the specified property set to value
local function get_body(record, property, value)
	for i, b in ipairs(record.body) do
		if b[property] == value then
			return b
		end
	end
	return nil
end

-- From ssl-enum-ciphers, remove value from table
local function remove(t, e)
	for i, v in ipairs(t) do
		if v == e then
			table.remove(t, i)
			return i
		end
	end
	return nil
end

-- From ssl-enum-ciphers
local function remove_high_byte_ciphers(t)
	local output = {}
	for i, v in ipairs(t) do
		if tls.CIPHERS[v] <= 255 then
			output[#output + 1] = v
		end
	end
	return output
end

-- From ssl-enum-ciphers, find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group, params)
	local results = {}
	local t = get_hello_table(host, protocol)
	local protocol_worked = false

	while (next(group)) do
		t["ciphers"] = group

		local records = try_params(host, port, t)
		if not records then
			return nil
		end
		local handshake = records.handshake

		if handshake == nil then
			local alert = records.alert
			if alert then
				stdnse.debug(2, protocol, "Got alert: %s", alert.body[1].description)
			elseif protocol_worked then
				stdnse.debug(2, protocol, "%d ciphers rejected. (No handshake)", #group)
			else
				stdnse.debug(1, protocol, "%d ciphers and/or protocol rejected. (No handshake)", #group)
			end
			break
		else
			local server_hello = get_body(handshake, "type", "server_hello")
			if not server_hello then
				stdnse.debug(2, protocol, "Unexpected record received.")
				break
			end
			if server_hello.protocol ~= protocol then
				stdnse.debug(1, protocol, "Protocol rejected. cipher: %s", server_hello.cipher)
				break
			else
				protocol_worked = true
				local name = server_hello.cipher
				stdnse.debug(2, protocol, "Cipher %s chosen.", name)
				if not remove(group, name) then
					stdnse.debug(1, protocol, "chose cipher %s that was not offered.", name)
					stdnse.debug(1, protocol, "removing high-byte ciphers and trying again.")
					local size_before = #group
					group = remove_high_byte_ciphers(group)
					stdnse.debug(1, protocol, "removed %d high-byte ciphers.", size_before - #group)
					if #group == size_before then
						-- No changes... Server just doesn't like our offered ciphers.
						break
					end
				else
					table.insert(results, name)
					-- Codigo para extraer informacion de ECDH, DH y claves.
					local info = tls.cipher_info(name)
					local kex = tls.KEX_ALGORITHMS[info.kex]
					local extra, kex_strength
					if kex.export then
						if info.kex:find("1024$") then
							kex_strength = 1024
						else
							kex_strength = 512
						end
					end
					if kex.anon then
						kex_strength = 0
					elseif have_openssl and kex.pubkey then
						local certs = get_body(handshake, "type", "certificate")
						local c, err
						if certs == nil then
							err = "no certificate message"
						else
							c, err = sslcert.parse_ssl_certificate(certs.certificates[1])
						end
						if not c then
							stdnse.debug(1, protocol, "Failed to parse certificate: %s", err)
						elseif c.pubkey.type == kex.pubkey then
							local sigalg = c.sig_algorithm:match("([mM][dD][245])") or
								c.sig_algorithm:match("([sS][hH][aA]1)")
							if sigalg then
								kex_strength = 0
							end
							local rsa_bits = tls.rsa_equiv(kex.pubkey, c.pubkey.bits)
							kex_strength = math.min(kex_strength or rsa_bits, rsa_bits)
							if c.pubkey.exponent then
								if openssl.bignum_bn2dec(c.pubkey.exponent) == "1" then
									kex_strength = 0
								end
							end
							if c.pubkey.ecdhparams then
								if c.pubkey.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
									extra = c.pubkey.ecdhparams.curve_params.curve
								else
									extra = string.format("%s %d", c.pubkey.ecdhparams.curve_params.ec_curve_type,
										c.pubkey.bits)
								end
							else
								extra = string.format("%s %d", kex.pubkey, c.pubkey.bits)
							end
						end
					end
					local ske
					if protocol == "TLSv1.3" then
						ske = server_hello.extensions.key_share
					elseif kex.server_key_exchange then
						ske = get_body(handshake, "type", "server_key_exchange")
						if ske then
							ske = ske.data
						end
					end
					if ske then
						local kex_info = kex.server_key_exchange(ske, protocol)
						if kex_info.strength then
							local kex_type = kex_info.type or kex.type
							if kex_info.ecdhparams then
								if kex_info.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
									extra = kex_info.ecdhparams.curve_params.curve
								else
									extra = string.format("%s %d", kex_info.ecdhparams.curve_params.ec_curve_type,
										kex_info.strength)
								end
							else
								extra = string.format("%s %d", kex_type, kex_info.strength)
							end
							local rsa_bits = tls.rsa_equiv(kex_type, kex_info.strength)
							if kex_strength and kex_strength > rsa_bits then
								kex_strength = rsa_bits
							end
							kex_strength = math.min(kex_strength or rsa_bits, rsa_bits)
						end
						if kex_info.rsa and kex_info.rsa.exponent == 1 then
							kex_strength = 0
						end
					end
					params[name] = {
						cipher_strength = info.size,
						kex_strength = kex_strength,
						extra = extra
					}
				end
			end
		end
	end
	return results, protocol_worked
end

-- From ssl-enum-ciphers, prepare ciphers to be sent to server
local function find_ciphers(host, port, protocol, params)
	local candidates = {}
	-- TLSv1.3 ciphers are different, though some are shared (ECCPWD)
	local tls13 = protocol == "TLSv1.3"
	for _, c in ipairs(sorted_keys(tls.CIPHERS)) do
		local info = tls.cipher_info(c)
		if (not tls13 and not info.tls13only)
			or (tls13 and info.tls13ok) then
			candidates[#candidates + 1] = c
		end
	end
	local ciphers = in_chunks(candidates, get_chunk_size(host, protocol))

	local results = {}

	-- Try every cipher.
	for _, group in ipairs(ciphers) do
		local chunk, protocol_worked = find_ciphers_group(host, port, protocol, group, params)
		if protocol_worked == nil then return nil end
		for _, name in ipairs(chunk) do
			table.insert(results, name)
		end
	end
	if not next(results) then return nil end

	return results
end

-- From ssl-enum-ciphers, function to see who has preference, client or server
local function compare_ciphers(host, port, protocol, cipher_a, cipher_b)
	local t = get_hello_table(host, protocol)
	t.ciphers = { cipher_a, cipher_b }
	local records = try_params(host, port, t)
	local server_hello = records.handshake and get_body(records.handshake, "type", "server_hello")
	if server_hello then
		stdnse.debug(2, protocol, "compare %s %s -> %s", cipher_a, cipher_b, server_hello.cipher)
		return server_hello.cipher
	else
		stdnse.debug(2, protocol, "compare %s %s -> error", cipher_a, cipher_b)
		return nil, string.format("Error when comparing %s and %s", cipher_a, cipher_b)
	end
end

-- From ssl-enum-ciphers, check if client can impose cipher suite over server
local function find_cipher_preference(host, port, protocol, ciphers)
	-- Too few ciphers to make a decision?
	if #ciphers < 2 then
		return "indeterminate", "Too few ciphers supported"
	end

	-- Do a comparison in both directions to see if server ordering is consistent.
	local cipher_a, cipher_b = ciphers[1], ciphers[2]
	stdnse.debug(1, protocol, "Comparing %s to %s", cipher_a, cipher_b)
	local winner_forwards, err = compare_ciphers(host, port, protocol, cipher_a, cipher_b)
	if not winner_forwards then
		return nil, err
	end
	local winner_backward, err = compare_ciphers(host, port, protocol, cipher_b, cipher_a)
	if not winner_backward then
		return nil, err
	end
	if winner_forwards ~= winner_backward then
		return "client", nil
	end
	return "server", nil
end

-- From ssl-enum-ciphers, start process of finding ciphers and organize them in the tables
local function try_protocol(host, port, protocol, upresults, params)
	local condvar = nmap.condvar(upresults)

	local results = stdnse.output_table()

	-- Find all valid ciphers.
	local ciphers = find_ciphers(host, port, protocol, params)
	if ciphers == nil then
		condvar "signal"
		return nil
	end

	if #ciphers == 0 then
		stdnse.debug("ERROR: NO CIPHER SUITES AVAILABLE")
		return nil
	end

	-- Note the server's cipher preference algorithm.
	local cipher_pref, cipher_pref_err = find_cipher_preference(host, port, protocol, ciphers)

	table.sort(ciphers)
	-- end

	for i, name in ipairs(ciphers) do
		local outcipher = { name = name, kex_info = params[name].extra, kex_strength = params[name].kex_strength }
		ciphers[i] = outcipher
	end

	results["ciphers"] = ciphers

	results["cipher preference"] = cipher_pref
	results["cipher preference error"] = cipher_pref_err

	upresults[protocol] = results
	condvar "signal"
	return nil
end

-- Main function to start threads in order to find cipher suites
function tryAllCipherSuites(host, port)
	local results = {}
	local params = {}

	local condvar = nmap.condvar(results)
	local threads = {}

	for name, _ in pairs(tls.PROTOCOLS) do
		stdnse.debug1("Trying protocol %s.", name)
		local co = stdnse.new_thread(try_protocol, host, port, name, results, params)
		threads[co] = true
	end

	repeat
		for thread in pairs(threads) do
			if coroutine.status(thread) == "dead" then threads[thread] = nil end
		end
		if (next(threads)) then
			condvar "wait"
		end
	until next(threads) == nil

	if not next(results) then
		return nil
	end

	return results, params
end

-- Auxiliary function to get value from key from table as for example cert.subject.commonName does not work idk why (TODO ?)
function get_value_from_key(t, key)
	for k, v in pairs(t) do
		if k == key then
			return v
		end
	end
	return nil
end

-- Auxiliary function to get values from SAN
local function locateSAN(extensions)
	for _, ext in pairs(extensions) do
		if ext.name and string.find(ext.name, "Subject Alternative Name") then
			return ext.value
		end
	end
	return nil
end

-- Auxiliary function to split SANs
local function splitSANs(sanString)
	local sans = {}
	for san in string.gmatch(sanString, "DNS:([^,]+)") do
		table.insert(sans, san:match("^%s*(.-)%s*$"))
	end
	return sans
end

-- Auxiliary function to get these values and not repeat code in functions
local function returnHostAndCommonNameAndSANs(host, certTable)
	local hostName = (host.name or nil)
	if hostName and string.match(host.name, "^www%.") then
		hostName = string.gsub(host.name, "^www%.", "")
	end

	-- TODO check if commonName can be obtained from cert rather than certTable
	local commonName = get_value_from_key(certTable.subject, "commonName")
	local SAN = locateSAN(certTable.extensions)
	local sanEntries = splitSANs(SAN) -- Divides SANs fields as individual entries

	return hostName, commonName, sanEntries
end

-- Check function to try to find IPs in the attributes of certificate
local function checkAvoidIPAddr(result, certTable)
	local pattern = "%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?"
	-- check if IP is found somewhere
	-- pairs is used for all type of indexes (numeric or non numeric, like for example dictionary), ipairs for numeric index (1,2,3 etc)
	for key, value in pairs(certTable.subject) do
		if type(value) == "string" and string.match(value, pattern) then
			result.checkAvoidIPAddr = (result.checkQualifiedDomainName or "\n\t[LOW ALERT]: ")
				.. "IP has been FOUND in SSL CERTIFICATE SUBJECT! "
				.. key
				.. " = "
				.. value
		end
	end
end

-- Check function to see if certificate is self signed
local function checkSelfSignedCert(result, cert)
	-- TODO: This basic check does not verify signature
	-- Apparently, Nmap doesn't support signature verification, it needs to be done separately with OpenSSL (or using LUA C API)
	-- openssl verify -CAfile <CA_cert.pem> <cert.pem>
	-- From https://svn.nmap.org/nmap/scripts/ssl-cert.nse
	-- Non verbose fields in a cert table are commonName", "organizationName", "stateOrProvinceName", "countryName"
	-- Simple equality does not work as tables are compared by reference. See https://www.lua.org/manual/5.4/manual.html#3.4.4
	local isSelfSigned = cert.subject.stateOrProvinceName == cert.issuer.stateOrProvinceName
		and cert.subject.organizationName == cert.issuer.organizationName
		and cert.subject.countryName == cert.issuer.countryName
	if isSelfSigned then
		result.selfSignedCheck =
		"Certificates must be signed by a trusted certificate authority (CA) to be trusted by users. For internal applications, an internal CA may be acceptable"
	end
end

-- Check function to see if wildcards are used in CN or SANs
local function checkWildcardScope(result, host, certTable)
	local _, commonName, sanEntries = returnHostAndCommonNameAndSANs(host, certTable)

	-- generic pattern to detect wildcard (*.domain.tld)
	local wildcardPattern = "^%*%.%w+%.%w+$"

	if commonName and string.match(commonName, wildcardPattern) then
		result.checkWildcardScope = "Generic WILDCARD found in Certificate Common Name -> " ..
			commonName
	end

	for _, san in ipairs(sanEntries) do
		if string.match(san, wildcardPattern) then
			result.checkWildcardScope = "Generic WILDCARD found in Certificate SAN -> " .. san
		end
	end
end

-- Check function to find domain name in certificate
local function checkDomainName(result, host, certTable)
	local hostName, commonName, sanEntries = returnHostAndCommonNameAndSANs(host, certTable)

	if hostName then
		if (hostName ~= " " or hostName ~= nil) and string.find(hostName, commonName) then
			return
		elseif (hostName ~= nil or hostName ~= "") and certTable.extensions then
			if sanEntries then
				for _, san in ipairs(sanEntries) do
					local escapedSan = san:gsub("%*", ".*") -- converts * into .*
					if string.match("^" .. escapedSan .. "$", hostName) then
						return
					end
				end
			end
		else
			if hostName ~= commonName then
				result.checkDomainName = "DOMAIN NAME and SUBJECT NAMES of SSL CERTIFICATE are NOT equal! -> "
					.. host.name
					.. " != "
					.. commonName
			end
		end
	else
		result.checkDomainName =
		"Unable to resolve HOST NAME void or invalid, unable to perform corresponding check. "
	end
end

-- Check function to see if compression is enabled
local function checkCompression(result, record)
	if record.body[1].compressor ~= "NULL" then
		result.compressorCheck = "COMPRESSION is ENABLED (vulnerable to CRIME vulnerability)!"
	end
end

local function checkTLSVersion(result, record)
	if record.body[1].protocol ~= "TLSv1.2" and record.body[1].protocol ~= "TLSv1.3" then
		result.TLSVersionCheck = "DEFAULT TLS VERSION is NOT SUPPORTED: " .. record.body[1].protocol
	end
end

-- Check functon to see if CBC or SHA-1 are used
local function checkCBCSHA(result, suite, msg)
	if string.find(suite.name, "CBC") then
		if string.match(suite.name, "SHA$") or string.find(suite.name, "SHA-1") then
			table.insert(result, msg .. "CBC and SHA-1: " .. suite.name)
		else
			table.insert(result,
				msg .. "CBC: " .. suite.name)
		end
	end

	if string.find(suite.name, "SHA-1") and not string.find(suite.name, "CBC") then
		table.insert(result,
			msg .. "SHA-1: " .. suite.name)
	end
end

local function checkDHKeyAndCurve(result, suite, tlsVersion)
	local curves = { "x25519", "prime256v1", "secp384r1" }

	if string.find(suite.name, "_DHE_") then
		if not string.find(suite.kex_info, "2048") then
			if not result.diffieHellmanKeySize then result.diffieHellmanKeySize = {} end
			table.insert(result.diffieHellmanKeySize,
				"[" .. tlsVersion .. "] DIFFIE HELLMAN KEY in cipher suite: " ..
				suite.name ..
				" does not have a 2048 bit key.")
		end
	else
		local curveFound = false;
		for _, curve in pairs(curves) do
			if string.find(suite.kex_info, curve) then
				curveFound = true;
				break
			end
		end

		if not curveFound then
			if not result.unsupportedTLSCurve then result.unsupportedTLSCurve = {} end
			table.insert(result.unsupportedTLSCurve,
				"[" .. tlsVersion .. "] Unsupported TLS Curve " ..
				suite.kex_info ..
				" for " .. suite.name)
		end
	end
end

-- Check function to centralize the review of cipher suites (CBC or SHA use, unsupported cipher suites use, client preference, DH keys and curves)
local function checkCipherSuites(result, cipherSuites)
	-- Initialize result categories as tables to store multiple findings
	result.high.unsafeCipherSuite = result.high.unsafeCipherSuite or {}
	result.critical.CBCSHA = result.critical.CBCSHA or {}

	for tlsVersion, details in pairs(cipherSuites) do
		-- Check cipher suites in all tls versions available in server
		if details.ciphers then
			for _, suite in pairs(details.ciphers) do
				if (tlsVersion == "TLSv1.2" or tlsVersion == "TLSv1.3") and string.find(suite.name, "DHE") then
					checkDHKeyAndCurve(result.high, suite, tlsVersion)
				end

				local isSafe = false
				for _, safeSuite in ipairs(safeCipherSuites) do
					if suite.name == safeSuite then
						isSafe = true
						break
					end
				end

				--if not isSafe and tlsVersion ~= "TLSv1.3" then
				if not isSafe then
					-- Add to high category
					table.insert(result.high.unsafeCipherSuite,
						"[" .. tlsVersion .. "] Server supports UNSAFE cipher suite: " .. suite.name)
					local msg = "[" .. tlsVersion .. "] Cipher suite supports VULNERABLE "
					-- Check for CBC vulnerability
					checkCBCSHA(result.critical.CBCSHA, suite, msg)
				end
			end
		end

		-- Check cipher preference
		if details["cipher preference"] == "client" then
			if not result.low.preference then result.low.preference = {} end
			table.insert(result.low.preference, "Client has PREFERENCE over server in " .. tlsVersion)
		end
	end
end

-- Check function to review encryption algorithm used in the public key
local function checkCertificateType(result, cert)
	stdnse.debug("\n\t[func:checkCertificateType]: Performing checkCertificateType")
	if cert.pubkey.type == "rsa" then
		if cert.pubkey.bits < 2048 then
			result.checkCertificateKeySize = "RSA public key size is too small (less than 2048 bits)"
		end
	elseif cert.pubkey.type == "ecdsa" then
		if cert.pubkey.bits < 256 then
			result.checkCertificateKeySize = "Elliptic curve public key size is too small (less than 256 bits)"
		end
	else
		result.checkCertificateType = "Certificate type is not RSA nor ECDSA"
	end
end

-- Check function to review certificate life span
local function checkCertificateLifespan(result, cert)
	stdnse.debug("\n[func:checkCertificateLifespan]: Initiating Certificate Lifespan check")

	if cert.validity.notAfter == nil or cert.validity.notBefore == nil then
		result.checkCertificateLifespan = "Certificate validity fields notAfter or notBefore absent"
	else
		local timediff = os.difftime(
			datetime.date_to_timestamp(cert.validity.notBefore),
			datetime.date_to_timestamp(cert.validity.notAfter)
		)
		if timediff < 90 * 24 * 60 * 60 then -- 90 days in seconds
			result.checkCertificateLifespan = "Certificate validity expires in less than 90 days"
		elseif timediff > 366 * 24 * 60 * 60 then -- 366 days in seconds
			result.checkCertificateLifespan = "Certificate validity expires in more than 366 days"
		end
	end
end

local function checkFQDNformat(nameToCheck, subdomainLimit)
	-- Prevent too-nested queries
	if subdomainLimit > 100 then
		subdomainLimit = 100
	end
	for i = 1, subdomainLimit do
		-- According to RFC1035 (Section 2.3.1)
		local pattern = "^(%a[%w-]-[%w])" .. string.rep("(%.[%a][%w-]-[%w])", i) .. "$"
		if nameToCheck:match(pattern) then
			return true
		end
	end

	return false
end

-- Check function to review FQDN
local function checkQualifiedDomainNameInHost(result, host)
	if host.name then
		if not checkFQDNformat(host.name, 10) then
			result.checkQualifiedDomainName = "Fully Qualified Domain Name in reverse DNS query is not valid: " ..
				host.name
		end
	else
		result.checkQualifiedDomainName =
		"Cannot get the Fully Qualified Domain Name with reverse DNS query, so no check can be performed. Please explicitly provide the FQDN of website instead of IP."
	end
end

-- Function to extract the HSTS Configuration
-- Inspired on https://svn.nmap.org/nmap/scripts/http-security-headers.nse
local function checkHSTSConfiguration(result, host, port)
	local response = http.head(host, port, "/")
	if response.header == nil then
		result.critical.checkHSTSConfiguration = "Cannot retrieve HTTP header from server"
	end
	local hstsHeader = response.header['strict-transport-security']
	if hstsHeader then
		local maxAge = hstsHeader:match("max%-age=(%d+);")
		if tonumber(maxAge) < 63072000 then -- 2 years
			result.medium.checkHSTSConfiguration = "HSTS is enabled but max-age is set to less than 2 years"
		end
	else
		result.critical.checkHSTSConfiguration = "HSTS not enabled for server"
	end
end

local function checkCNAndSANAttributes(result, host, certTable)
	local _, commonName, sanEntries = returnHostAndCommonNameAndSANs(host, certTable)
	local primaryFQDN = ""
	local domainFound = false
	if commonName then
		if checkFQDNformat(commonName, 10) then
			primaryFQDN = commonName
		else
			result.checkQualifiedDomainName = (result.checkQualifiedDomainName or "") ..
				"\n\tFully Qualified Domain Name in Common Name is not valid: " .. commonName
		end
	end
	for _, domain in pairs(sanEntries) do
		if domain == primaryFQDN then
			domainFound = true
		end
		if not checkFQDNformat(domain, 10) then
			result.checkCNAndSANAttributes = (result.checkCNAndSANAttributes or "") ..
				"SAN entry does not contain valid FQDN: " .. domain .. "\n"
		end
	end
	if not domainFound then
		result.checkCNAndSANAttributes = "Primary FQDN " ..
			primaryFQDN .. " not present in SAN Entries (as 1st entry)"
	end
end

-- Main function
function action(host, port)
	local result = stdnse.output_table()
	result.critical = {}
	result.high = {}
	result.medium = {}
	result.low = {}

	stdnse.debug("\n[func: action]: Initiating %s NSE script: %s, port %d", SCRIPT_NAME, host.ip, port.number)

	local statusClientHello, response = clientHello(host, port)
	if statusClientHello and response then
		stdnse.debug("\n[func: action]: ClientHello sent and got response back")
		local check, record = reviewServerHello(response)

		if check ~= false and record then
			-- if CLIENT HELLO and SERVER HELLO communication have been established successfully
			checkCompression(result.critical, record)
			checkTLSVersion(result.high, record)
			local cipherSuites = tryAllCipherSuites(host, port)
			-- print_table(cipherSuites)
			checkCipherSuites(result, cipherSuites) -- here result is passed, as there are two alerts with different level
		else
			print(
				"------------------------------------------------------------------------------------------------------------------")
			print(
				"ERROR: ServerHello response was 'alert', unable to proceed with handshake and corresponding checks...")
			print(
				"------------------------------------------------------------------------------------------------------------------")
		end
	else
		stdnse.debug("\n[func: action]: Error when getting CLIENT HELLO or when receiving response")
	end

	local statusCertificate, cert = sslcert.getCertificate(host, port)
	stdnse.debug("\n[func:action]: Certificate retrieval status: %s", tostring(statusCertificate))

	if statusCertificate then
		local certTable = output_tab(cert) -- we store in table the values of certificate in order to access to them in a easier way

		-- print("\n\n--------------------SSL CERTIFICATE---------------------------")
		-- print_table(certTable) -- print table so we see all the data available (to compare checks)
		-- print("\n--------------------------------------------------------------\n\n")
		-- print("\n\n--------------------HOST---------------------------")
		-- print_table(host) -- print table so we see all host values (to compare checks)
		-- print("\n--------------------------------------------------------------\n\n")
		-- una prueba para ver esta funcion..devuelve los algoritmos ciphers pero no en el formato que queremos ni tampoco te dice donde utiliza que
		-- local ciphers = {}
		-- ciphers = openssl.supported_ciphers()
		-- print_table(ciphers)
		checkSelfSignedCert(result.critical, cert)
		checkCertificateType(result.high, cert)
		checkCertificateLifespan(result.medium, cert)
		checkQualifiedDomainNameInHost(result.low, host)
		checkAvoidIPAddr(result.low, certTable)
		checkDomainName(result.medium, host, certTable)
		checkWildcardScope(result.low, host, certTable)
		checkHSTSConfiguration(result, host, port)
		checkCNAndSANAttributes(result.low, host, certTable)
	else
		print(
			"------------------------------------------------------------------------------------------------------------------")
		print(
			"ERROR: SSL Certificate cannot be obtained due to SSL connection error, unable to proceed with corresponding checks...")
		print(
			"------------------------------------------------------------------------------------------------------------------")
	end


	for key, check in pairs(result) do
		local alertCount = 0
		if type(check) == "table" then
			-- Contar alertas dentro de 'check'
			for _, alertTable in pairs(check) do
				if type(alertTable) == "table" then
					for _, _ in pairs(alertTable) do
						alertCount = alertCount + 1
					end
				end
			end

			-- Imprimir conteo de alertas
			print(string.format("%s ALERTS: %d", string.upper(tostring(key)), alertCount))
			print("*********************")

			-- Imprimir mensajes de alerta
			for key2, alert in pairs(check) do
				if type(alert) == "table" and next(alert) ~= nil then
					print(key2 .. " - ")
					for _, message in pairs(alert) do
						print("\t" .. tostring(message))
					end
				end
			end
			print("*********************")
		end
	end



	return result
end
