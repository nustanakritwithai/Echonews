/* Read-only progressive enhancement. No network requests, storage, analytics or credentials. */
'use strict';
const search=document.querySelector('#news-search'), source=document.querySelector('#news-source');
const reports=[...document.querySelectorAll('.report')], count=document.querySelector('#result-count');
function filterNews(){
  const query=search.value.trim().toLocaleLowerCase('th');let visible=0;
  for(const report of reports){
    const match=report.dataset.title.toLocaleLowerCase('th').includes(query)&&
      (source.value==='all'||report.dataset.publisher===source.value);
    report.hidden=!match;if(match)visible++;
  }
  count.textContent=`${visible} จาก ${reports.length} รายงาน · จากฟีดที่เลือก ช่วง 7 วันก่อนการอัปเดตล่าสุด`;
  document.querySelector('#no-results').hidden=visible!==0||reports.length===0;
}
search.addEventListener('input',filterNews);source.addEventListener('change',filterNews);
function updateAge(){
  const health=document.querySelector('#health');const last=Date.parse(health.dataset.lastSuccess);
  if(!Number.isFinite(last)||Date.now()-last>36*60*60*1000||last>Date.now()+5*60*1000){
    health.classList.add('stale');
    document.querySelector('#health-label').textContent='ข้อมูลอาจเก่า · ยังไม่มีการดึงสำเร็จใน 36 ชั่วโมงที่ผ่านมา';
  }
}
updateAge();setInterval(updateAge,60000);
