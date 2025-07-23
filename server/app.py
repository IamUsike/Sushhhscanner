from flask import Flask,request,jsonify,render_template
from flask_cors import CORS 
import asyncio
import threading
import json 
import time 
from directory_enum import DirectoryEnumerator
import logging

app=Flask(__name__)
CORS(app)

logging.baseConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

active_scans={}
scan_results={}

@app.route('/')
def index():
    return render_templaet('index.html')    


@app.route('/api/scan',method=['POST'])
def start_scan():
    try:
        data=request.get_json()
        target_url=data.get('target_url')
        wordlist_type=data.get('wordlist_type','common')
        max_workers=data.get('max_workers',50)
        delay=data.get('delay',0.1)

        if not target_url:
            return jsonify({'error':'target_url is required'}),400 

        scan_id=f"scan_{int(time.time())}_{hash(target_url)}"

        active_scans[scan_id]={
                'status':'running',
                'target_url':target_url,
                'wordlist_type':wordlist_type,
                'start_time':time.time(),
                'progress':0,
                'resutls':[]
                }


        def run_scan():
            try:
                loop=asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                enumer=DirectoryEnumerator()
                results=loop.run_until_complete(
                        enumer.scan_target(target_url,wordlist_type,max_workers,delay)
                        )

                active_scans[scan_id]['status']='completed'
                active_scans[scan_id]['results']=results
                active_scans[scan_id]['end_time']=time.time()
                active_scans[scan_id]=results

            except Exception as e:
                logger.error(f"Scan error: {str(e)}")
                active_scans[scan_id]['status']='error'
                active_scans[scan_id]['error']=str(e)
            finally:
                loop.close()

        thread = threading.Thread(target=run_scan)
        thread.daemon=True
        thread.start()

        return jsonify({
            'scan_id':scan_id,
            'status':'started',
            'target_url':target_url,
            'wordlist_type':wordlist_type
            })

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error':str(e)},500)


@app.route('/api/scan/<scan_id>/status',methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error':'Scan not found'}),404 

    scan_info=active_scan[scan_id]
    return jsonify(sacn_info)

@app.route('/api/scan/<scan_id/results',methods=['GET'])
def get_scan_resutls(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error':'Scan result not found'}),404 

    return jsonify(scan_result[scan_id])

@app,route('/api/scans',method=['GET'])
def list_scan():
    return jsonify({
        'active_scans':list(active_scans.keys()),
        'completed_scans':list(scan_results.keys())
        })

@app.route('/api/wordlists',methods=['GEt'])
def get_wordlists():
    enumer=DirectoryEnumerator()
    return jsonify({
        'wordlists':list(enumer.wordlists.keys()),
        'wordlist_info':{
            name:len(word) for name, words in enumer.wordlist.items()
            }
        })

@app.route('/api/scan/<scan_id>/cancel',methods=['POST'])
def cancel_scan(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error':'Scan not found'}), 404

    if active_scans[scan_id]['status']=='running'
        active_scans[scan_id]['status']='cancelled'
        return jsonify(['message':'Scan cancelled'])
    else:
        return jsonify({'error':'Scan is not running'}),404 


@app.route('/api/health',methods=['GET'])
def health_check():
    return jsonify({
        'status':'healthy',
        'active_scans':len([s for s in active_scans.values() if s['status']=='running']),
        'compelted_scans':len(scan_results)
        })

if __name__=='main':
    app.run(debug=True,host='0.0.0.0',port=5000)
