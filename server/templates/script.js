let currentScanId = null;
let statusInterval = null;

document.getElementById('scanForm').addEventListener('submit',async(e)=>{
  e.preventDefault();
  await startScan();
});

document.getElementById('cancelBtn').addEventListener('click',async()=>{
  await cancelScan();
});

async function startScan(){
  const targetUrl=document.getElementById('targetUrl').value;
  const wordlistType=docuemnt.getElementById('wordlistType').value;
  const maxWorkers=parseInt(document.getElementById('maxWorkers').value);
  const delay=parseFloat(document.getElementById('delay').value);

  try{
    const response=await fetch('/api/scan',{
      method:'POST',
        headers:{
          'Content-Type':'application/json',
        },
        body:JSON.stringiy({
          target_url:targetUrl,
          wordlist_type:wordlistType,
          max_workers:maxWorkers,
          delay:delay
        })
    });

    const data=await response.json();

    if(response.ok){
      currentScanId=data.scan_id;
      showProgreses();
      startStatusPolling();
      updateUI('running');
    }else{
      alert('Error: '+ data.error);
    }
  }catch(error){
    alert('Error starting scan: '+error.message);
  }
}


async function cancelScan(){
  if(!currentScanId) return;

  try{
    const response = await fetch('/api/scan/${currentScanId}/cancel',{
      method:'POST';
    });

    if(response.ok){
      updateUI('cancelled');
      stopStatusPolling();
    }
  }catch(error){
    alert('Error cancelling scan: '+error.message);
  }
}


function startStatusPolling(){
  statusInterval = setInterval(async ()=>{
    if(!currentScanId) return;

    try{
      const response=await fetch(`/api/scan/${currentScanId}/status`);
      const data= await response.json();

      if(data.status ==='compeleted'){
        stopStatusPolling();
        await loadResults();
        updateUI('completed');
      } else if(data.status==='error'){
        stopStatusPolling();
        updateUI('error',data.error);
      }else if(data.status==='running'){
        updateProgress(data.progress || 0);
      }
    }catch(error){
      console.error('Error polling status: ',error);
    }
  },1000);
}


function stopStatusPolling(){
  if (statusInterval){
    clearInterval(statusInterval);
    statusInterval=null;
  }
}

async function loadResults(){
  try{
    const response = await fetch(`/api/scan/${currentScanId}/results`);
    const data=await response.json();

    displayResults(data);
    displayStats(data);
  }catch(error){
    console.error('Error loading results: ',error);
  }
}

function showProgress(){
  document.getElementById('progressCard').classList.remove('hidden');
  document.getElementById('statsCard').classList.add('hidden');
  document.getElementById('resultsCard').classList.add('hidden');
}

function updateProgress(progress){
  document.getElementById('progressFill').style.width=progress + '%';
  document.getElementById('progressText').textContent = Math.round(progress)+'%';
}

function updateUI(status,error=null){
  const statusDiv=document.getElementById('status');
  const startBtn = document.getElementById('startBtn');
  const cancelBtn=document.getElementById('cancelBtn');

  statusDiv.className='status' + status;

  if (status==='running'){
    statusDiv.textContent="Scan is running . . .";
    startBtn.disabled=true;
    cancelBtn.style.display='inline-block';
  }else if(status==='completed'){
    statusDiv.textContent='Scan completed successfully!';
    startBtn.disabled=false;
    cancelBtn.style.display='none';
  }else if(status==='error'){
    statusDiv.textContent='Scan failed: '+error;
    startBtn.disabled=false;
    cancelBtn.style.display='none';
  }else if(status==='canceled'){
    statusDiv.textContent='Scan was cancelled';
    startBtn.disabled=false;
    cancelBtn.style.display='none';
  }
}

function displayStats(data){
  const statsGrid = document.getElementById('statsGrid');
  const stats=data.scan_stats;

  const duration=stats.end_time && stats.start_time ? Math.round(stats.end_time-stats.start_time) : 0;

  statsGrid.innerHTML=`
  <div class="stat-card">
    <div class="stat-number">${data.found_count}</div>
    <div class="stat-label">Items Found</div>
  </div>

  <div class="stat-card">
    <div class="stat-number">${data.total_checked}</div>
    <div class="stat-label">Total Checked</div>
  </div>

  <div class="stat-card">
    <div class="stat-number">${stats.successful_requests}</div>
    <div class="stat-label">Successful Requests</div>
  </div>  

  <div class="stat-card">
    <div class="stat-number">${duration}s</div>  
    <div class="stat-label">Duration</div>
  </div>
  `;

  document.getElementById('satsCard').classList.remove('hidden');
}

function displayResults(data){
  const resultsTable=document.getElementById('resultsTable');
  if(!data.results || data.results.length === 0){
    resutlsTable.innerHTML=`<p>No results found.</p>`;
    docuemnt.getElementById('resultsCard').classList.remove('hidden');
    return;
  }
  let tableHTML=`
  <table class="results-table">
    <thead>
      <tr>
        <th>URL</th>
        <th>Status</th>
        <th>Type</th>
        <th>Size</th>
        <th>Response Time</th>
        <th>Title</th>
      </th>
    </thead>
  </tbody>
  `;

  data.results.forEach(result=>{
    const statusClass=`status-${result.status_code}`;
    const type=result.is_directory ? 'Directory' : 'File';
    const size=result.content_length>0 ? formatBytes(result.content_length) : '-';

    tableHTML+=`
    <tr>
      <td><a href="${result.url}" target="_blank">${result.url}</a></td>
      <td><span class="status-code ${statusClass}">${result.status_code}</span></td>
      <td>${type}</td>
      <td>${size}</td>
      <td>${result.reponse_time.toFixed(3)}s</td>
      <td>${result.title || "-" }</td>
      </tr>
    `;
  });

  tableHTML += `</tbody></table>`
  resutlsTable.innerHTML=tableHTML;
  document.getElementById('resultsCard').classList.remove('hidden');

}

function formatBytes(bytes){
  if (bytes===0) return '0 B';
  const k=1024;
  const sizes = ['B','KB','MB','GB'];
  const i=Math.floor(Math.log(bytes)/Math.log(k));
  return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+' '+sizes[i];
}
