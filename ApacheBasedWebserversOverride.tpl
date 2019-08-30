
tpl 1.8 module ApacheBasedWebserversOverride;

metadata
    origin := "Traversys";
    _name := "Apache HTTPD-based Webservers Override";
    tree_path:= "Custom", "Traversys", "Apache HTTPD Override";
end metadata;

from SupportingFiles.Tables import Publishers 1.4;
from SupportingFiles.CDM_Mapping import SoftwareServerType 1.0;
from DiscoveryFunctions import DiscoveryFunctions 1.0;
from ApacheBasedWebservers import ApacheWebsites 3.1,
                                  Products 3.1,
                                  KnownApachePackages 1.2,
                                  ApacheWebserverFuncs 1.4,
                                  ApacheBasedWebserver 3.1;

pattern ApacheBasedWebserverOverride 1.0
    '''
        Custom Pattern Override for ApacheBasedWebserver 3.1

        Updated active LD_LIBRARY_PATH commands to a script failure.
    '''

    metadata
        publishers := "Apache Foundation", "IBM", "Oracle", "HP", "Red Hat";
        products := "Apache Webserver", "IBM HTTP Server", "Oracle HTTP Server", "HP Apache-based Web Server",
                    "HP HP-UX Apache-based Web Server", "JBoss Enterprise Web Server";
        categories := "Application Server Software Platforms";
        cdm_software_server_type := SoftwareServerType.WEBServer;
        urls := "http://www.apache.org/", "http://www-306.ibm.com/software/webservers/httpservers/",
                "http://www.orafaq.com/faqhttp.htm", "http://www.hp.com/products1/unix/webservers/index.html",
                "https://www.redhat.com/en/resources/jboss-enterprise-web-server";
        additional_attributes := "publisher", "config_file", "server_root", "ebs_sid";
        expected_ports := 80, 443;
    end metadata;

    overview
        tags TKU, Webserver, Apache, IHS, httpd, TKU_2018_02_01;
        overrides ApacheBasedWebserver;
    end overview;

    constants
        ibmhttp_paths := [ regex '(?i)IBM(HTTPD|IHS)',
                           regex '(?i)\bIBM.*(HTTP|IHS)',
                           regex '(?i)IHS'];

        oraclehttp_paths := [ regex '/(?:orcl|ora[^/]*)/[^ ]*/Apache',
                              regex '(?i)(?:orcl|ora[^\\]*)\\.*\bApache',
                              regex '(?i)\bOHS\b.*\bhttpd'];

        apache_found_paths := [ regex '\bapache[^ ]*/(?:sbin|bin)/[^ ]*\bhttpd$',
                                regex '\bapps/apache[^ ]*/(?:sbin|bin)/httpd$',
                                regex '/usr/sbin/httpd$',
                                regex '\bapache[^ ]*/(?:sbin|bin)/[^ ]*\bhttpd[-_]prefork$',
                                regex '/usr/sbin/(?:httpd|apache)\d$',
                                regex '/usr/sbin/httpd\d*[-_\.](?:prefork|worker|event)$',
                                windows_cmd 'apache',
                                windows_cmd 'httpd' ];
        redhat_paths := [ regex '(?i)jboss-ews'];
    end constants;

    triggers
        on process := DiscoveredProcess where cmd matches unix_cmd 'httpd\d?'
                                           or cmd matches windows_cmd 'httpd\d?'
                                           or cmd matches regex '(?i)\bhttpd\d?[-_\.](?:prefork|worker|event)$'
                                           or cmd matches regex '(?i)\bapache\d?(?:\.exe)?$';
    end triggers;

    body
        // If we have command-line args, store them in a local variable for efficiency
        args := "";
        if process.args then
            args := process.args;
        end if;

        // We could possibly have triggered on Netscape/iPlanet/Sun HTTP server process (ns-httpd or ns-httpd.exe)
        // If this is the case, stop further processing
        if process.cmd matches regex '(?i)ns-httpd' or process.cmd matches regex '(?i)iplanet' or process.cmd matches regex '(?i)\\resin-'
            or process.cmd matches regex '(?i)\bMPS\b' or process.cmd matches regex '(?i)sunone' then
            stop;
        end if;

        // We could also possbily have triggered on Apache Stronghold processes. If this is the case, stop further processing
        if args matches regex '/stronghold(?:\b|_)' then
            stop;
        end if;

        // Check if the parents cmd matches the child's cmd, if it does then we are dealing with a
        //  child process, so ignore - we only want to create an instance for the parent process.
        parent := discovery.parent(process);
        if parent and text.lower(parent.cmd) = text.lower(process.cmd) then
            stop;
        end if;

        host := model.host(process);
        full_version := "";
        product_version := '';
        build := "";
        discovered_publisher := "";
        publisher := "";
        product := "";
        type := '';
        config_file := "";
        server_root := "";
        results := [];
        sbin_dir := '';

        // PUBLISHER EXTRACTION (PATH)
        // See if we can get the publisher from the path
        // Reason: We should attempt to extract publisher from path as we cannot identify Oracle Apache server otherwise
        // Nevertheless we cannot identify HP-UX publisher un this case

        // Check if it is IBM's version
        for cmd_line_regex in ibmhttp_paths do
            if process.cmd matches cmd_line_regex then
                discovered_publisher := "ibm";
                break;
            end if;
        end for;
        // If not IBM HTTPD, check if it is Oracle HTTPD
        if not discovered_publisher then
            for cmd_line_regex in oraclehttp_paths do
                if process.cmd matches cmd_line_regex then
                    discovered_publisher := "oracle";
                    break;
                end if;
            end for;
        end if;

        // Check whether it is Apache Foundation HTTPD
        if not discovered_publisher then
            for cmd_line_regex in apache_found_paths do
                if process.cmd matches cmd_line_regex then
                    discovered_publisher := "apache";
                    break;
                end if;
            end for;
        end if;

        // Check if it Red Hat Jboss EWS
        if not discovered_publisher then
            for cmd_line_regex in redhat_paths do
                if process.cmd matches cmd_line_regex then
                    discovered_publisher := "red hat";
                    break;
                end if;
            end for;
        end if;

        // Create version command dependant on the Operating System
        version_commands := [];
        if host.os_class = "Windows" then
            full_cmd_path := regex.extract(process.cmd, regex '(?i)(^\w:\\.+)\\\S+\.exe$', raw '\1');
            if full_cmd_path then
                // Oracle HTTPD or Apache HTTPD
                list.append(version_commands, '"%process.cmd%" -V');
                if discovered_publisher = "ibm" or not discovered_publisher then
                    // IBM HTTPD
                    list.append(version_commands, 'findstr HTTP "%full_cmd_path%\\..\\version.signature"');
                end if;
            end if;
        else
            full_cmd_path := regex.extract(process.cmd, regex '^(/\S+)/(?:httpd|apache)\d*[-_\.]?(?:prefork|worker|event)?$', raw '\1');
            if full_cmd_path then

                if host.os_type = 'Ubuntu Linux' or host.os_type = 'Debian Linux' then
                    sbin_dir := regex.extract(process.cmd, regex '^(/.+/s?bin)/[^/]+$', raw '\1');
                    if sbin_dir then
                        list.append(version_commands, '"%sbin_dir%/apache2ctl" -V');
                    end if;
                end if;

                // Oracle HTTPD or Apache HTTPD or HP
                list.append(version_commands, 'strings -a %process.cmd% | egrep "Apache/|Oracle-HTTP-Server" | head -n 3');

                version_command := "";
                // In some cases the following command requires a path to library directory set
                // Will try to use default HTTP Server library path
                install_root := regex.extract(process.cmd, regex '^(/.+)/s?bin/[^/]+$', raw '\1');
                if install_root then
                    if host.os_type = 'Solaris' and host.os_arch matches '64' then
                        version_command := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%install_root%/lib:/usr/sfw/lib/64 %process.cmd% -V 2> /dev/null";
                    else
                        version_command := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:%install_root%/lib %process.cmd% -V 2> /dev/null";
                    end if;
                elif host.os_type = 'Solaris' and host.os_arch matches '64' then
                    version_command := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/sfw/lib/64 %process.cmd% -V 2> /dev/null";
                end if;

                if version_command then
                    list.append(version_commands, version_command);
                end if;

                if discovered_publisher = "ibm" or not discovered_publisher then
                    // IBM HTTPD
                    list.append(version_commands, 'cd %full_cmd_path%; grep "HTTP" ../version.signature');
                end if;
            end if;
        end if;

        // We can do active versioning version from the normal version command
        // (version_command) and the secondary version command (secondary_cmd)
        // If both a possible we do both, and store both results in a list
        for version_command in version_commands do
            // *command_info_start
            // command_solaris := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<installation_path>/lib:/usr/sfw/lib/64 <path_to_trigger_process> -V"
            // command_windows := '"<path_to_trigger_process>" -V'
            // command_solaris := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/sfw/lib/64 <path_to_trigger_process> -V"
            // command_unix := 'cd <installation_path>; grep "HTTP" ../version.signature'
            // command_unix := "<installation_dir>/sbin/apache2ctl -V"
            // command_windows := 'findstr HTTP "<installation_path>\version.signature"'
            // command_unix := 'strings -a <path_to_trigger_process> | egrep "Apache/|Oracle-HTTP-Server" | head -n 3'
            // command_unix := "LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<installation_path>/lib <path_to_trigger_process> -V"
            // reason := "Versioning, server_root and configuration_file attributes extraction"
            // when := "Yes, if Apache installation path is known"
            // *command_info_end
            ran_cmd := discovery.runCommand(process, version_command);
            if ran_cmd and ran_cmd.result and not ran_cmd.result has substring 'No such file or directory' then
                list.append(results, ran_cmd.result);
            end if;
        end for;

        // For Red Hat JBoss path versioning will be used
        if not discovered_publisher = 'red hat' then
            // ACTIVE VERSIONING
            // PUBLISHER EXTRACTION (ACTIVE)
            // Cycle through the results of active versioning commands to try and find
            // version and publisher. As soon as we find a version as a publisher we
            // quit.  This means the pattern will always use the default version command
            // in preference to secondary version command
            for result in results do
                log.debug("Apache @ %host.name%: Version command was ran, output is: %result%");

                if not discovered_publisher then
                    // We need to have 'discovered_publisher' in lower case as table Publishers contains publishers in such a way
                    // We will deal with it later.
                    discovered_publisher := regex.extract(text.lower(result), regex '(ibm|hp-ux|hp|apache|oracle|red hat)', raw '\1');
                end if;

                // Publisher specific regexes:
                // 'IBM[_\s]+HTTP[_\s]+Server[/\s]+(\d+(?:\.\d+)*)' - IBM HTTPD
                // '(\d+(?:\.\d+)*)\s+Oracle-HTTP-Server'           - Oracle HTTP
                // 'HP Apache-based Web Server/(\d+(?:\.\d+)*)'     - HP
                // 'HP-UX_Apache-based_Web_Server/(\d+(?:\.\d+)*)'  - HP-UX case
                // ''/jboss-ews/base/(\d+(?:\.\d+)*)'               - Red Hat

                version_regexes := [ regex 'IBM[_\s]+HTTP[_\s]+Server[/\s]+(\d+(?:\.\d+)*)',
                                     regex '(\d+(?:\.\d+)*)\s+Oracle-HTTP-Server',
                                     regex 'HP Apache-based Web Server/(\d+(?:\.\d+)*)',
                                     regex 'HP-UX_Apache-based_Web_Server/(\d+(?:\.\d+)*)'];

                for regexv in version_regexes do
                    full_version := regex.extract(result, regexv, raw '\1');
                    if full_version then
                        log.debug("Apache @ %host.name%: Full version %full_version% found");
                        break;
                    end if;
                end for;

                if not full_version then
                    full_version := regex.extract(result, regex "Apache/(\d+(?:\.\d+)*)", raw '\1');
                end if;

                if discovered_publisher and full_version then
                    log.debug("Publisher: %discovered_publisher% & Version: %full_version% extracted. Breaking loop.");
                    break;
                end if;
            end for;
        end if;
        // PATH VERSIONING
        if process.cmd matches regex '~' then
           full_process_cmd := DiscoveryFunctions.pathNormalization(host,process.cmd);
        else
           full_process_cmd := "%process.cmd%";
        end if;
        // Check the path if the cmd did not return the version
        if not full_version then
            // Debug message
            log.debug("Apache @ %host.name%: could not obtain version using active method, will try path");
            // Define full path of the binary
            if args then
               full_proc_path := "%full_process_cmd% %args%";
            else
               full_proc_path := "%full_process_cmd%";
            end if;
            // Check the path to see if it contains the version number
            full_version := regex.extract(full_proc_path, regex '(?i)apache(?:_|/|-|\.|\\|)(\d(?:\.\d+)?(?:\.\d+)?(?:-\d+)?)', raw '\1');
            if not full_version then
                full_version := regex.extract(full_proc_path, regex '(?i)/ihs[-_]?(?:(\d(?:\.\d+)?(?:\.\d+)?(?:-\d+)?))', raw '\1');
            end if;

            if not full_version then
                full_version := regex.extract(full_proc_path, regex '(?i)HTTPServer(\d)(\d?)(\d?)', raw '\1.\2.\3');
                full_version := text.rightStrip(full_version, '.');
            end if;
            // Check JBoss specific path
            if not full_version then
                full_version := regex.extract(full_proc_path, regex '(?i)/jboss-ews/base/(?:(\d(?:\.\d+)?(?:\.\d+)?(?:-\d+)?))', raw '\1');
            end if;

            if full_version and size(full_version) < 6  then // If we have a build number the length of the version will be greater than 5
               full_version := text.replace(text.replace(full_version, '-', '.'), '_', '.');
            end if;
        end if;

        // Select which publisher information should be used
        // SETTING TYPE, publisher, product name
        if discovered_publisher = 'hp-ux' then
            publisher := Publishers[discovered_publisher];
            log.debug("Publisher has been found '%discovered_publisher%' which is a special case");
            type := Products[text.upper(discovered_publisher)][0];
            product := Products[text.upper(discovered_publisher)][1];
        elif discovered_publisher then
            log.debug("Publisher has been found '%discovered_publisher%', will convert to normalised string");
            publisher := Publishers[discovered_publisher];
            log.debug("Publisher after normalization - %publisher%");
            type := Products[publisher][0];
            product := Products[publisher][1];
            log.debug("Publisher retrieved from KnownPublishers table '%publisher%'");
        else
            type := Products[discovered_publisher][0];  // default from table
            product := Products[discovered_publisher][1]; //default from table
            // If cannot work out publisher, likely just Apache
            publisher := "Apache"; // Set after because type and product should be set based on default value in the Products table
        end if;

        log.debug("Final setting for Publisher is: %publisher%, for product is: %product% and for type: %type%");

        // PACKAGE VERSIONING
        // If version is still not defined then try package versioning
        if not full_version then
            // Debug message
            log.debug("Apache @ %host.name%: Unable to acquire version from a command or path, will try package query");
            // Create list of packages to check for based on the identified Publisher
            if publisher = "Apache" then
                check_packages := [regex '^httpd',
                                   regex '^SUNWapch2r$',
                                   regex '^SUNWapchu$',
                                   regex '^SUNWapch2u$',
                                   regex '^SUNWapch22r$',
                                   regex '^SUNWapch22u$',
                                   regex '^COVLapache',
                                   regex '^apache2',
                                   regex '^(?i)Apache HTTP Server',
                                   regex 'web/server/apache-13',
                                   regex 'web/server/apache-22'];

            elif publisher = "IBM" then
                check_packages := [regex '^IBMHTTP',
                                   regex '^ISIHS',
                                   regex '^IHS6\.base$',
                                   regex '^(?i)IBM HTTP Server'];
            else
                check_packages := [];
            end if;

            // Get packages
            if size(check_packages) > 0 then
                packages := model.findPackages(host, check_packages);
            else
                packages := [];
            end if;

            // If at least one package matched the regex list then identify which one
            //  to use
            if publisher = "Apache" and size(packages) > 0 then
                package_count := size(packages);
                // Debug message
                log.debug("Apache @ %host.name%: Found %package_count% package(s)");
                //
                // Package Preference Algorithm
                //
                // The following code is used to identify the best package to use for
                //  versioning of the product
                //
                // It uses a combination of the package name and the preference number,
                //  defined in the table at the beginning of the module, to identify
                //  whether the package we are looking at is more trusted that the
                //  current 'most trusted' package
                //

                // Default preference defined, the default returned from the table is 100
                preference := 101;

                // Loop through packages
                for package in packages do
                    // Debug message
                    log.debug("Apache @ %host.name%: Found package %package.name%, with version '%package.version%'");

                    // Get the package preference by lookingup the name in the table, if
                    //  the name isn't in the table then 100 is returned and the first
                    //  package not in the table will be selected as the most trusted
                    package_preference := KnownApachePackages[package.name];

                    // Check if the preference of the current package is less than the
                    //  current 'most trusted' package.
                    if package_preference < preference then

                        // Debug message
                        log.debug("Apache @ %host.name%: Preference for %package.name%, is less than %preference%");
                        log.debug("Apache @ %host.name%: Assigning %package.version% from package %package.name% to version");
                        log.debug("Apache @ %host.name%: Changing preference value to %package_preference%");

                        if package.name matches '^SUNW' and 'description' in package then
                            full_version := regex.extract(package.description, '(?i)Version\s*(\d+(?:\.\d+)*)', raw'\1');
                            preference := package_preference;
                        elif 'version' in package then
                            full_version := package.version;
                            preference := package_preference;
                        end if;
                    end if;
                end for;

            elif publisher = "IBM" and size(packages) > 0 then
                // in case of IBM, choose the first package
                package := packages[0];
                if "version" in package then
                    full_version := package.version;
                    log.debug("full_version is: %full_version%");
                end if;
            end if;
        end if;

        // Get server_root and config_file.
        server_root, config_file := ApacheWebserverFuncs.getServerRoot(host, process, results);

        // SETTING BUILD
        if full_version then
            build := regex.extract(full_version, regex '-(\d+)$', raw '\1');
        end if;

        // SETTING PRODUCT VERSION
        if full_version then
            product_version := regex.extract(full_version, regex '(\d+(?:\.\d+)?)', raw '\1');
            if not product_version then
                product_version := full_version;
            end if;
        end if;

        //Retrieving list of installed modules
        //Loaded Modules:
        //win32_module (static)
        installed_modules := [];
        installed_modules_str := "";

        //retrieving modules list from config file
        if config_file then
            // *filepath_info_start
            // filepath_unix := "<configuration_file>"
            // filepath_windows := "<configuration_file>"
            // reason := "Obtain installed modules"
            // when := "Only if config file known"
            // *filepath_info_end
            conf_file := discovery.fileGet(host, config_file);
            if conf_file and conf_file.content then
                //for customer view
                installed_modules := regex.extractAll(conf_file.content, regex '(?m)^\s*LoadModule\s+(\S+)\s');
            end if;
        end if;
        //retrieving modules list from command output
        if not installed_modules and full_process_cmd and full_process_cmd matches regex '(^\w:\\|^/)' then
            ran_cmd := "";
            if full_version then
                if DiscoveryFunctions.getMaxVersion(full_version, "1.9.99") = "1.9.99" then
                    if host.os_class = "Windows" then
                        command := '"%full_process_cmd%" -h';
                    else
                        command := 'PRIV_RUNCMD %full_process_cmd% -h';
                    end if;
                else
                    if host.os_class = "Windows" then
                        command := '"%full_process_cmd%" -M';
                    elif sbin_dir and (host.os_type = 'Ubuntu Linux' or host.os_type = 'Debian Linux') then
                        command := '"%sbin_dir%/apache2ctl" -M';
                    else
                        command := 'PRIV_RUNCMD %full_process_cmd% -M';
                    end if;
                end if;
                // *command_info_start
                // command_windows := "<full_process_cmd> -M"
                // command_unix := "PRIV_RUNCMD <full_process_cmd> -M"
                // command_unix := "<installation_dir>/sbin/apache2ctl -M"
                // command_unix := "PRIV_RUNCMD <full_process_cmd> -h"
                // command_windows := "<full_process_cmd> -h"
                // reason := "Returns list of installed modules"
                // privileges := true
                // when := "Only if server root is known"
                // *command_info_end
                ran_cmd := discovery.runCommand(host, command);
            end if;
            if ran_cmd and ran_cmd.result and ran_cmd.result has substring "Loaded Modules" then
                //for customer view
                installed_modules := regex.extractAll(ran_cmd.result, regex "(?i)(\S+_module)");
            end if;
        end if;

        if installed_modules then
            //converting into str to perform searches
            installed_modules_str := text.join(installed_modules, " | ");
        end if;

        // SETTING ADDITIONAL ATTRIBUTES
        tw_meta_data_attrs := ["publisher"];
        if config_file then
            tw_meta_data_attrs := tw_meta_data_attrs + ["config_file"];
        end if;
        if server_root then
            tw_meta_data_attrs := tw_meta_data_attrs + ["server_root"];
        end if;
        if installed_modules then
            tw_meta_data_attrs := tw_meta_data_attrs + ["installed_modules"];
        end if;

        // SETTING NAME
        if type = "Apache HTTPD-based Webserver" then
            name_type := "Webserver";
        else
            name_type := type;
        end if;
        if product_version then
            name := '%name_type% %product_version% on %host.name%';
            short_name := '%name_type% %product_version%';
        else
            name := '%name_type% on %host.name%';
            short_name := name_type;
        end if;

        // Create Software instance
        // Instance based SI is to be created only in case config_file attribute is set
        if config_file then
            if host.os_class = 'Windows' then
                config_file_hash := text.hash(text.lower(config_file));
            else
                config_file_hash := text.hash(config_file);
            end if;
            apache_si := model.SoftwareInstance(key := '%config_file_hash%/%type%/%host.key%',
                                                name := name,
                                                short_name := short_name,
                                                type := type,
                                                version := full_version,
                                                product_version := product_version,
                                                build := build,
                                                config_file := config_file,
                                                server_root := server_root,
                                                publisher := publisher,
                                                product := product,
                                                installed_modules := installed_modules,
                                                _installed_modules_str := installed_modules_str,
                                                _tw_meta_data_attrs := tw_meta_data_attrs);
            log.info("Instance-based SI created for %name% on %host.name%");
        else
            if args then
                bfh := text.lower('%process.cmd% %process.args%');
            else
                bfh := text.lower(process.cmd);
            end if;
            afh := text.hash(bfh);
            apache_si := model.SoftwareInstance(key_group := afh,
                                                name := name,
                                                short_name := short_name,
                                                type := type,
                                                version := full_version,
                                                product_version := product_version,
                                                build := build,
                                                server_root := server_root,
                                                publisher := publisher,
                                                product := product,
                                                installed_modules := installed_modules,
                                                _installed_modules_str := installed_modules_str,
                                                _tw_meta_data_attrs := tw_meta_data_attrs);
            log.info("Grouped SI created for %name% on %host.name%");
        end if;

        // associate child processes to each instance (or grouped instance provided that abs path to binary)
        children := discovery.descendents(process); // get all child processes
        if children and full_cmd_path then
            inference.associate(apache_si, children);
        end if;

        // Adding additional attribute to the Oracle HTTP SI to enable
        // linking to E-Business Suite SI
        if apache_si.publisher = "Oracle" and config_file then
            // *filepath_info_start
            // filepath_unix := "<configuration_file_path>"
            // filepath_windows := "<configuration_file_path>"
            // reason := "Website SoftwareComponent modelling, 'ebs_sid' attribute extraction"
            // when := "Only if publisher is Oracle or ApacheWebsites.create_website_sc option is enabled. This requires config_file attribute to be set in Apache SI"
            // *filepath_info_end
            config_file := discovery.fileGet(process, '%config_file%');

            // Setting E-Business Suite SID
            if config_file and config_file.content and apache_si.publisher = "Oracle" then
                log.debug("HTTP Config file extracted.");
                ebs_sid := regex.extract(config_file.content, regex "(?i)DocumentRoot *.+portal[/\\](.+)_", raw "\1");
                if ebs_sid then
                    apache_si.ebs_sid := ebs_sid;
                    log.debug("E-Business SID: %ebs_sid% added to SI.");
                end if;
            end if;
        end if;
    end body;
end pattern;
