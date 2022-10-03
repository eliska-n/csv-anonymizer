import yaml
import csv
import re
import hashlib
import ipaddress
import random
import argparse


def hash_sha256_to_chars(col, length=10):
	hashed = hashlib.sha256(col.encode("utf-8")).hexdigest()
	return hashed[:length]
	# TODO: vyměnit hexdigest za hezky pismenka


def anonymize_username(col):
	email = anonymize_email(col)
	if email == "not email":
		return hash_sha256_to_chars(col)
	return email


def anonymize_email(col):
	if len(col) == 0:
		return ""
	regex_result = re.match(r"^(.*)@(.*)(\..*)$", col)
	if regex_result is None:
		return "not email"
	username = hash_sha256_to_chars(regex_result.group(1))
	domain = hash_sha256_to_chars(regex_result.group(2))

	return "{}@{}{}".format(username, domain, regex_result.group(3))



def anonymize_ipv4(col):
	try:
		ip = ipaddress.ip_address(col)
	except ValueError:
		return "not ip"

	if ip.is_private:
		return '1.1.1.1'  # TODO: anonymize private ips

	else:
		return "{}.{}.{}.{}".format(ip.packed[0], ip.packed[1], random.randint(0, 255), random.randint(0, 255))  # čtvrť vs. město - jak moc potřebuji data zašifrovat? bezpečnost vs. přesnost



def anonymize_ip(col):
	if len(col) == 0:
		return ""

	if "." in col:
		return anonymize_ipv4(col)
	else:
		return  # TODO: ipv6


def anonymize_filepath(col):
	if len(col) == 0:
		return ""
	name, suffix = col.rsplit(".", 1)


def tranform_row(row, anondef):
	for colname, coldef in anondef.items():
		col = row.pop(colname)
		if col is None:
			continue

		fnctname = coldef.get('anonymize', 'drop')
		if fnctname == "email":
			col = anonymize_email(col)

		elif fnctname == "ip":
			col = anonymize_ip(col)

		elif fnctname == "filepath":
			col = anonymize_filepath(col)

		elif fnctname == "username":
			col = anonymize_username(col)

		elif fnctname == "hash":
			col = hash_sha256_to_chars(col)

		elif fnctname == "drop":
			col = None
		else:
			raise NotImplementedError("Missing anonymization function: '{}'".format(fnctname))

		if col is not None:
			row[colname] = col

	return row


def main(inp, out, anondef):
	with open(anondef, "rb") as f:
		anondef = yaml.safe_load(f)

	with open(inp, "r") as fi, open(out, 'w') as fo:
		reader = csv.DictReader(fi, delimiter=",")
		fieldnames = list(reader.fieldnames)
		for colname, coldef in anondef.items():
			if coldef.get('anonymize', 'drop') == "drop":
				fieldnames.remove(colname)
		writer = csv.DictWriter(fo, fieldnames=fieldnames)
		writer.writeheader()
		for row in reader:
			new_row = tranform_row(row, anondef)
			writer.writerow(new_row)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		description='Anonymize CSV.',
		epilog="Created by Eliska Novotna & Ales Teska."
	)

	parser.add_argument(
		'--input', dest='INPUT', action='store',
		default="./data/applogman_sample.csv",
		help="Specifies the input file (default: './data/applogman_sample.csv')"
	)

	parser.add_argument(
		'--output', dest='OUTPUT', action='store',
		default="./data/anonymized_data.csv",
		help="Specifies the input file (default: './data/anonymized_data.csv')"
	)

	parser.add_argument(
		'--def', dest='ANONDEF', action='store',
		default="./anondef.yaml",
		help="Specifies the YAML file with definition of anonymization (default: './anondef.yaml')"
	)

	args = parser.parse_args()
	main(inp=args.INPUT, out=args.OUTPUT, anondef=args.ANONDEF)
