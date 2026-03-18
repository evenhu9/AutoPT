import argparse
import os
import time
import jsonlines

from utils import load_config, print_AutoRT
from psm import States
from autopt import AutoPT



def argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--name', 
        type=str, 
        help='The name of the vulnerability'
    )
    parser.add_argument(
        '--ip_addr', 
        type=str, 
        help='The ip address of the target machine'
    )

    args=parser.parse_args()
    return args

def main():
    print_AutoRT()
    args = argument_parser()
    pname = str(args.name)
    ip_addr = str(args.ip_addr)
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'config.yml')
    config = load_config(config_file_path)

    models = config['test']['models']
    states = States(pname, config)
    autopt = AutoPT(pname, config, ip_addr, states)

    for model_name in models:
        llm, res_name = autopt.llm_init(config, model_name)
        autort_graph = autopt.state_machine_init(llm=llm)
        #目录确认
        os.makedirs(os.path.dirname(res_name), exist_ok=True)
        if not os.path.exists(res_name):
            with open(res_name, 'w') as f:
                pass
        with jsonlines.open(res_name, 'a') as f:
            for i in range(1):
                start_time = time.time()
                try:
                    autopt.state_machine_run(graph = autort_graph, name=pname, ip_addr=ip_addr)
                except Exception as e:# 超出上下文宽度报错
                    if 'string too long' in str(e) or 'This model\'s maximum context' in str(e):
                        states.history = [str(e)]
                        autopt.flag = 'failed'
                    else:
                        raise e
                        
                runtime = time.time() - start_time
                log = autopt.log(i, runtime)
                f.write(log)
                states.refresh()

if __name__ == '__main__':
    main()