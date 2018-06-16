.PHONY: run_prod run_prod_basic run_debug_basic

run_prod:
	nohup authbind python3 run.py --prod &

run_debug:
	nohup authbind python3 run.py --debug &

run_prod_basic:
	python3 server.py --prod

run_debug_basic:
	python3 server.py --debug
