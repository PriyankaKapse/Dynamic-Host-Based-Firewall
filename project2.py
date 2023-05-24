import iptc
import logging

# Configure logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# To Create a rule to allow incoming SSH connections
def create_ssh_rule():
    # Create new rule for the INPUT chain
    rule = iptc.Rule()
    rule.protocol = "tcp"
    rule.target = rule.create_target("ACCEPT")
    
    # Set the source and destination ports for SSH
    rule.match = rule.create_match("tcp")
    rule.match.dport = "22"
    
    # Add the rule to the INPUT chain
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)
    
    logging.info("SSH rule created successfully.")
    print("SSH rule created successfully.")


# To Remove the SSH rule
def remove_ssh_rule():
    # Find the SSH rule in the INPUT chain
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    for rule in chain.rules:
        if rule.protocol == "tcp" and rule.match and rule.match.dport == "22":
            chain.delete_rule(rule)
            logging.info("SSH rule removed successfully.")
            print("SSH rule removed successfully.")
            return
    
    logging.warning("SSH rule not found.")
    print("SSH rule not found.")

# To Update the SSH rule based on specific conditions
def update_ssh_rule(condition):
    # Remove the existing SSH rule
    remove_ssh_rule()
    
    # Create a new rule based on the condition
    if condition:
        create_ssh_rule()
    
    logging.info("SSH rule updated based on condition.")
    print("SSH rule updated based on condition.")



create_ssh_rule()

# To remove the SSH rule, uncomment below line
# remove_ssh_rule()

# Update the SSH rule if it's outside of working hours (weekdays, 9 AM to 5 PM)
import datetime

now = datetime.datetime.now()
weekday = now.weekday()
hour = now.hour

if weekday < 5 and (hour < 9 or hour >= 17):
    condition = True
else:
    condition = False

update_ssh_rule(condition)
