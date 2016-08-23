import sys, os, argparse, logging, time, re

def create_logger(logger_name):
    "Creates logger. Returns created logger and logger filename"

    log_filename = logger_name + '_' + time.strftime("%d%m%Y") + '_' + str(os.getpid()) + '.log'

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_filename, mode = 'w')
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger, log_filename

def index_containing_substring(the_list, substring, start_index):
    for s in the_list[start_index:]:
        if substring in s:
            return the_list.index(s, start_index)

    return -1

def check_table(table, all_file, logger):
    start_index = 0
    for row in table:
        local = row.split('|')
        if local[1].strip() <> local[2].strip():
            start_index = index_containing_substring(all_file, row, start_index) + 1
            logger.error("Line " + str(start_index) + ":")
            logger.error("\t" + local[0] + " : " + local[1].strip() + " != " + local[2].strip())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Finds differences in test logs for SDT and SSDT tables')
    parser.add_argument('input_path', action = 'store', help = 'input path')

    args = parser.parse_args()
    input_path = args.input_path
    
    logger, log_filename = create_logger('check_ssdt_names_py')

    if not os.path.exists(input_path):
        logger.error("Invalid input path: " + input_path)
        logging.shutdown()
        sys.exit(1)

    logger.debug(input_path)
    result = []

    with open(input_path) as f:
        result = f.readlines()

    if len(result) == 0:
        logger.error("Empty file")
        logging.shutdown()
        sys.exit(1)

    begin_sdt = result.index("[+] !wa_ssdt\n")
    end_sdt = result.index("[+] !wa_w32psdt\n", begin_sdt)
    begin_ssdt = end_sdt
    end_ssdt = result.index("[+] !wa_w32psdtflt\n", begin_ssdt)
    begin_ssdt_flt = end_ssdt
    end_ssdt_flt = result.index("[+] !wa_lxsdt\n", begin_ssdt_flt)

    if begin_sdt == 0 or end_sdt == 0 or begin_ssdt == 0 or end_ssdt == 0:
        logger.error("SDT or SSDT position not found")
        logging.shutdown()
        sys.exit(1)

    sdt_tmp = result[begin_sdt:end_sdt]
    ssdt_tmp = result[begin_ssdt:end_ssdt]
    ssdt_flt_tmp = result[begin_ssdt_flt:end_ssdt_flt]

    pattern = re.compile(r'^[|]\s+([0-9a-fA-F]+)[|]0x')

    sdt = []
    for row in sdt_tmp:
        if pattern.match(row):
            sdt.append(row[7:])

    ssdt = []
    for row in ssdt_tmp:
        if pattern.match(row):
            ssdt.append(row[7:])

    ssdt_flt = []
    for row in ssdt_flt_tmp:
        if pattern.match(row):
            ssdt_flt.append(row[7:])

    if len(sdt) <> 0:
        logger.debug("Checking SDT")
        check_table(sdt, result, logger)
    else:
        logger.error("Empty SDT")

    if len(ssdt) <> 0:
        logger.debug("Checking SSDT")
        check_table(ssdt, result, logger)
    else:
        logger.error("Empty SSDT")

    if len(ssdt_flt) <> 0:
        logger.debug("Checking SSDT Filter")
        check_table(ssdt_flt, result, logger)

    logging.shutdown()
    sys.exit(0)
