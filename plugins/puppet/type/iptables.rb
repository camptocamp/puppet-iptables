module Puppet
  @@rules = {}

  @@current_rules = {}

  @@table_counters = {
    'filter' => 1,
    'nat'    => 1,
    'mangle' => 1,
    'raw'    => 1
  }

  # pre and post rules are loaded from files
  # pre.iptables post.iptables in /etc/puppet/iptables
  @@pre_file  = "/etc/puppet/iptables/pre.iptables"
  @@post_file = "/etc/puppet/iptables/post.iptables"

  # location where iptables binaries are to be found
  @@iptables_dir = "/sbin"

  @@finalized = false

  newtype(:iptables) do
    @doc = "Manipulate iptables rules"

    newparam(:name) do
      desc "port number to be manipulated"

      validate do |value|
        raise "port must be number" unless /^\d+$/.match(value)
      end
    end

    newparam(:chain) do
      desc "holds value of iptables -A parameter.
                  Default value is 'INPUT'"
      defaultto "INPUT"
    end

    newparam(:proto) do
      desc "holds value of iptables --protocol parameter.
                  Possible values are: 'tcp', 'udp', 'icmp', 'all'.
                  Default value is 'all'"
      newvalues(:tcp, :udp, :icmp, :all)
      defaultto "all"
    end

    newparam(:table) do
      desc "one of the following tables: 'nat', 'mangle',
                  'filter' and 'raw'. Default one is 'filter'"
      newvalues(:nat, :mangle, :filter, :raw)
      defaultto "filter"
    end

    newparam(:source) do
      desc "value for iptables --source parameter"
    end

    newparam(:destination) do
      desc "value for iptables --destination parameter"
    end

    newproperty(:ensure) do
      newvalue(:open) { }
      newvalue(:close) { }
    end

    def load_current_rules(numbered = false)
      if( numbered )
        # reset table counters to 0
        @@table_counters = {
          'filter' => 0,
          'nat'    => 0,
          'mangle' => 0,
          'raw'    => 0
        }
      end

      table         = ''
      loaded_rules  = {}
      table_rules   = {}
      counter       = 1

      `#{@@iptables_dir}/iptables-save`.each { |l|
        if /^\*\S+/.match(l)
          table = self.matched(l.scan(/^\*(\S+)/))

          # init loaded_rules hash
          loaded_rules[table] = {} unless loaded_rules[table]
          table_rules = loaded_rules[table]

          # reset counter
          counter = 1

        elsif /^-A/.match(l)
          # matched rule
          chain = self.matched(l.scan(/^-A (\S+)/))

          source = self.matched(l.scan(/-s (\S+)/))
          source = "0.0.0.0/0" unless source

          destination = self.matched(l.scan(/-d (\S+)/))
          destination = "0.0.0.0/0" unless destination

          protocol = self.matched(l.scan(/-p (\S+)/))
          protocol = "all" unless protocol

          dport = self.matched(l.scan(/--dport (\S+)/))
          dport = "" unless dport

          jump = self.matched(l.scan(/-j (\S+)/))
          jump = "" unless jump

          data = {
            'name'        => dport,
            'chain'       => chain,
            'proto'       => protocol,
            'table'       => table,
            'source'      => source,
            'destination' => destination
          }

          if( numbered )
            table_rules[counter.to_s + " " +l.strip] = data

            # we also set table counters to indicate amount
            # of current rules in each table, that will be needed if
            # we decide to refresh them
            @@table_counters[table] += 1
          else
            table_rules[l.strip] = data
          end

          counter += 1
        end
      }
      return loaded_rules
    end

    def matched(data)
      if data.instance_of?(Array)
        data.each { |s|
          if s.instance_of?(Array)
            s.each { |z|
              return z.to_s
            }
          else

            return s.to_s
          end
        }
      end
      nil
    end

    # Fix this function
    def load_rules_from_file(rules, file_name, action)
      if File.exist?(file_name)
        counter = 0
        File.open(file_name, "r") do |infile|
          while (line = infile.gets)
            next unless /^\s*[^\s#]/.match(line.strip)
            table = line[/-t\s+\S+/]
            table = "-t filter" unless table
            table.sub!(/^-t\s+/, '')
            rules[table] = [] unless rules[table]
            rule =
              { 'table'         => table,
                'full rule'     => line.strip,
                'alt rule'      => line.strip}

            if( action == :prepend )
              rules[table].insert(counter, rule)
            else
              rules[table].push(rule)
            end

            counter += 1
          end
        end
      end
    end

    def finalize
      # load pre and post rules
      load_rules_from_file(@@rules, @@pre_file, :prepend)
      load_rules_from_file(@@rules, @@post_file, :append)

      # add numbered version to each rule
      @@table_counters.each_key { |table|
        rules_to_set = @@rules[table]
        if rules_to_set
          counter = 1
          rules_to_set.each { |rule|
            rule['numbered rule'] = counter.to_s + " "+rule["full rule"]
            rule['altned rule']   = counter.to_s + " "+rule["alt rule"]
            counter += 1
          }
        end
      }

      # On the first round we delete rules which do not match what
      # we want to set. We have to do it in the loop until we
      # exhaust all rules, as some of them may appear as multiple times
      while self.delete_not_matched_rules > 0
      end

      # Now we need to take care of rules which are new or out of order.
      # The way we do it is that if we find any difference with the
      # current rules, we add all new ones and remove all old ones.
      if self.rules_are_different
        # load new new rules
        benchmark(:notice, "rules have changed...") do
          # load new rules
          @@table_counters.each { |table, total_do_delete|
            rules_to_set = @@rules[table]
            if rules_to_set
              rules_to_set.each { |rule_to_set|
                `#{@@iptables_dir}/iptables -t #{table} #{rule_to_set['alt rule']}`
              }
            end
          }

          # delete old rules
          @@table_counters.each { |table, total_do_delete|
            current_table_rules = @@current_rules[table]
            if current_table_rules
              current_table_rules.each { |rule, data|
                `#{@@iptables_dir}/iptables -t #{table} -D #{data['chain']} 1`
              }
            end
          }
        end

        @@rules = {}
      end

      @@finalized = true
    end

    def finalized?
        if defined? @@finalized
            return @@finalized
        else
            return false
        end
    end

    def rules_are_different
      # load current rules
      @@current_rules = self.load_current_rules(true)

      @@table_counters.each_key { |table|
        rules_to_set = @@rules[table]
        current_table_rules = @@current_rules[table]
        current_table_rules = {} unless current_table_rules
        if rules_to_set
          rules_to_set.each { |rule_to_set|
            return true unless current_table_rules[rule_to_set['numbered rule']] or current_table_rules[rule_to_set['altned rule']]
          }
        end
      }

      return false
    end

    def delete_not_matched_rules
      # load current rules
      @@current_rules = self.load_current_rules

      # count deleted rules from current active
      deleted = 0;

      # compare current rules with requested set
      @@table_counters.each_key { |table|
        rules_to_set = @@rules[table]
        current_table_rules = @@current_rules[table]
        if rules_to_set
          if current_table_rules
            rules_to_set.each { |rule_to_set|
              full_rule = rule_to_set['full rule']
              alt_rule  = rule_to_set['alt rule']
              if    current_table_rules[full_rule]
                current_table_rules[full_rule]['keep'] = 'me'
              elsif current_table_rules[alt_rule]
                current_table_rules[alt_rule]['keep']  = 'me'
              end
            }
          end
        end

        # delete rules not marked with "keep" => "me"
        if current_table_rules
          current_table_rules.each { |rule, data|
            if data['keep']
            else
              `#{@@iptables_dir}/iptables -t #{table} #{rule.sub("-A", "-D")}`
              deleted += 1
            end
          }
        end
      }
      return deleted
    end

    def evaluate
      self.finalize unless self.finalized?
      return super
    end

    def self.clear
      @@rules = {}

      @@current_rules = {}

      @@table_counters = {
        'filter' => 1,
        'nat'    => 1,
        'mangle' => 1,
        'raw'    => 1
      }

      @@finalized = false
      super
    end


    def initialize(args)
      super(args)

      table = value(:table).to_s
      @@rules[table] = [] unless @@rules[table]
      array = @@rules[table]

      jump = "ACCEPT"
      jump = "DROP" unless value(:ensure) == :open

      full_string = "-A " + value(:chain).to_s
      if value(:source).to_s != ""
        full_string += " -s " + value(:source).to_s
      end
      if value(:destination).to_s != ""
        full_string += " -d " + value(:destination).to_s
      end
      alt_string  = full_string
      if value(:proto).to_s != "all"
        alt_string  += " -p " + value(:proto).to_s +
          " -m " + value(:proto).to_s
        full_string += " -p " + value(:proto).to_s
      end
      if value(:name).to_s != ""
        full_string += " --dport " + value(:name).to_s
        alt_string  += " --dport " + value(:name).to_s
      end

      full_string += " -j " + jump
      alt_string  += " -j " + jump

      @@rules[table].
        push({ 'name'          => value(:name).to_s,
               'chain'         => value(:chain).to_s,
               'proto'         => value(:proto).to_s,
               'table'         => value(:table).to_s,
               'source'        => value(:source).to_s,
               'destination'   => value(:destination).to_s,
               'full rule'     => full_string,
               'alt rule'      => alt_string})
    end
  end
end
