import os
import sys
import csv
import json
import asn1
import pycurl
import logging
import argparse
from io import BytesIO
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


def get_certificates_chain(url):
    """

    Return certificates chain
    Used pycurl, BytesIO

    :param url: url
    :type url: str
    :return: SSL-certificates chain
    :rtype: list

    """
    response = BytesIO()                                                            # stream for response
    curl = pycurl.Curl()                                                            # cURL object
    curl.setopt(pycurl.URL, url)                                                    # set url
    curl.setopt(pycurl.OPT_CERTINFO, 1)                                             # get certificate information
    curl.setopt(pycurl.SSL_VERIFYHOST, 0)                                           # don't verify cert. name vs host
    curl.setopt(pycurl.SSL_VERIFYPEER, 0)                                           # don't verify peer's cert.
    curl.setopt(pycurl.WRITEDATA, response)                                         # output stream
    curl.perform()                                                                  # request
    chain = []                                                                      # chain initialization
    for data_field in curl.getinfo(pycurl.INFO_CERTINFO):                           # certificates cycle
        for info_field in data_field:                                               # fields cycle
            if info_field[0] == 'Cert':                                             # if certificate value
                chain.append(info_field[1])                                         # add it to chain
    return chain                                                                    # return result


def get_subject_alternative_names(url):
    """

    Subject alternative names
    Used pyOpenSSL, asn1

    :param url: url
    :type url: str
    :return: subject alternative names from certificate extension
    :rtype: list

    """
    names = []                                                                      # result initialization
    certificate = load_certificate(FILETYPE_PEM, get_certificates_chain(url)[0])    # load server certificate
    extensions = certificate.get_extension_count()                                  # extensions count
    i, data = 0, None                                                               # cycle initialization
    while i < extensions:                                                           # extensions cycle
        extension = certificate.get_extension(i)                                    # get extension
        if extension.get_short_name() == b'subjectAltName':                         # if subjectAltName
            decoder = asn1.Decoder()                                                # decoder initialization
            decoder.start(extension.get_data())                                     # start decoder
            while not decoder.eof():                                                # decoding cycle
                tag = decoder.peek()                                                # get next tag
                if tag.typ == asn1.Types.Constructed:                               # if constructed tag
                    decoder.enter()                                                 # enter to tag
                elif tag.typ == asn1.Types.Primitive:                               # if primitive tag
                    names.append(decoder.read()[1].decode())                        # add name to names list
            break                                                                   # all names extracted
        i += 1                                                                      # next extension
    return sorted(names)                                                            # return alternative names list


def task_termination(error_message, condition=True, code='0'):
    """
    Return code and message to stdout for Groovy script - error termination

    :param error_message: error message
    :type error_message str
    :param condition: condition for exit
    :type condition bool
    :param code exit code
    :type code str
    """
    if condition:
        logging.error(error_message)
        if code.isdigit():
            code = int(code)
        if code == 0:
            print("1%s" % error_message)
        sys.exit(code)

# Entry point


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s --- %(message)s', level=logging.INFO)
    task_termination('Two parameters required: urls(csv), domains(json)', len(sys.argv) != 3)
    parser = argparse.ArgumentParser(description='Get and compare alternative names lists')
    parser.add_argument("urls", help='urls list in csv')
    parser.add_argument("domains", help='json file for compare')
    args = parser.parse_args()
    task_termination('No such urls csv file: %s' % args.urls, not os.path.isfile(args.urls))
    task_termination('No such domains json file: %s' % args.domains, not os.path.isfile(args.domains))
    with open(args.domains, 'r') as domains_file:
        try:
            domains = json.load(domains_file)
        except json.JSONDecodeError:
            task_termination('JSON file has incorrect format: %s' % args.domains, True)
    with open(sys.argv[1]) as brands:
        csv_reader = csv.reader(brands)
        messages = ""
        for row in csv_reader:
            if row[0] not in domains:
                message = 'URL %s omitted in file %s' % (row[0], args.domains)
                logging.error(message)
                messages += '%s\n' % message
                continue
            try:
                for name in get_subject_alternative_names(row[0]):
                    if name not in domains[row[0]]:
                        message = 'Domain %s omitted for %s in file %s' % (name, row[0], args.domains)
                        logging.error(message)
                        messages += '%s\n' % message
            except Exception as e:
                logging.error('error: %s' % str(e))
    print("0%s" % messages)
