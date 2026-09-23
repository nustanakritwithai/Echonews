// Every event, name, observation and assessment below is a fictional UI fixture.
// These are not live reports, external news feeds or AI verification results.
export const VERSION='0.1.0';
export const TOPICS=['ทั้งหมด','พื้นที่และชุมชน','เทคโนโลยี','การเดินทาง','สิ่งแวดล้อม'];
export const KINDS={observation:'รายงานจากพื้นที่',question:'คำถาม',opinion:'ความคิดเห็น',correction:'ข้อทักท้วง'};
export const ROOMS=[
{id:'canal-demo',title:'น้ำบนถนนคลองเหนือ แต่ละจุดเป็นอย่างไร?',short:'น้ำบนถนนคลองเหนือ',category:'พื้นที่และชุมชน',place:'ย่านคลองเหนือ · พื้นที่สมมติ',theme:'water',updated:'17:42',intro:'คนละจุด คนละเวลา อาจเล่าต่างกัน มาดูเสียงต้นฉบับก่อนสรุป',quote:'“ช่วงตลาดมีน้ำ แต่ฝั่งสะพานยังต้องดูแยกกัน”',claims:[
{id:'water-surface',text:'มีน้ำบนผิวถนนบริเวณหน้าตลาด',scope:'หน้าตลาดคลองเหนือ · 17:20–17:30 ในสถานการณ์จำลอง',support:['v01','v02'],counter:[],freshness:'UNKNOWN'},
{id:'road-closed',text:'บริเวณสะพานผ่านไม่ได้ทุกช่องทาง',scope:'สะพาน A · 17:35 ในสถานการณ์จำลอง',support:['v03'],counter:['v04'],freshness:'UNKNOWN'},
{id:'water-later',text:'ระดับน้ำในช่วงถัดไปจะเพิ่มหรือไม่',scope:'ยังไม่มีข้อมูลจำลองสำหรับคำถามนี้',support:[],counter:[],freshness:'UNKNOWN'}]},
{id:'mobile-ai-demo',title:'ลองใช้ผู้ช่วย AI บนมือถือ ประสบการณ์จริงต่างกันตรงไหน?',short:'ทดลองผู้ช่วย AI บนมือถือ',category:'เทคโนโลยี',place:'ห้องทดลองชุมชน · โจทย์สมมติ',theme:'tech',updated:'16:55',intro:'ผลทดสอบและความเห็นคนละเรื่องกัน ดูเงื่อนไขของแต่ละเสียง',quote:'“งานเดียวกัน แต่เครื่องและวิธีทดสอบยังไม่เหมือนกัน”',claims:[
{id:'offline-test',text:'การทดสอบชุด A ทำงานโดยปิดอินเทอร์เน็ต',scope:'อุปกรณ์ A · บันทึกทดลองที่สร้างขึ้นสำหรับเดโม',support:['v07'],counter:[],freshness:'UNKNOWN'},
{id:'all-devices',text:'ผลการทดสอบใช้กับมือถือทุกเครื่องได้หรือไม่',scope:'ยังไม่มีข้อมูลการทดลองข้ามอุปกรณ์',support:[],counter:[],freshness:'UNKNOWN'}]},
{id:'bus-demo',title:'จุดรับรถชุมชนย้ายชั่วคราว เสียงจากสองจุดรับ',short:'จุดรับรถชุมชนเปลี่ยน',category:'การเดินทาง',place:'ชุมชนสวนตะวัน · พื้นที่สมมติ',theme:'transit',updated:'16:40',intro:'แยกสิ่งที่เห็นจากสิ่งที่ได้ยินต่อมา เพื่อไม่ให้การแชร์กลายเป็นการยืนยัน',quote:'“เห็นป้ายย้ายจุดรับแล้ว แต่ยังไม่ทราบเวลาสิ้นสุด”',claims:[
{id:'bus-stop-move',text:'มีป้ายระบุจุดรับชั่วคราวหน้าสวน',scope:'ป้ายจำลองจุด A · เวลา 16:20',support:['v11'],counter:[],freshness:'UNKNOWN'},
{id:'bus-end-time',text:'กำหนดกลับมาใช้จุดรับเดิม',scope:'บันทึกจำลองยังไม่ระบุ',support:[],counter:[],freshness:'UNKNOWN'}]},
{id:'garden-demo',title:'ลานเล็ก ๆ กลายเป็นพื้นที่แลกต้นไม้ของชุมชน',short:'พื้นที่แลกต้นไม้ของชุมชน',category:'สิ่งแวดล้อม',place:'ลานสวนตะวัน · พื้นที่สมมติ',theme:'garden',updated:'15:50',intro:'หลายคนช่วยเติมรายละเอียด ตั้งแต่กิจกรรมถึงคำถามที่ยังไม่มีคำตอบ',quote:'“อยากให้มีมุมสอนปลูกสำหรับคนเริ่มต้นด้วย”',claims:[
{id:'garden-activity',text:'มีจุดแลกต้นไม้บริเวณลาน A',scope:'กิจกรรมสมมติ · บันทึก 15:20',support:['v15'],counter:[],freshness:'UNKNOWN'},
{id:'garden-next',text:'กิจกรรมรอบต่อไปจัดเมื่อไร',scope:'ยังไม่มีข้อมูลในชุดจำลอง',support:[],counter:[],freshness:'UNKNOWN'}]}
];
export const VOICES=[
{id:'v01',roomId:'canal-demo',name:'มิน',kind:'observation',time:'17:22',text:'ผมอยู่หน้าตลาดในสถานการณ์จำลอง เห็นน้ำบนผิวถนนช่วงหน้าร้าน ไม่ได้เห็นตลอดทั้งถนนนะครับ',evidence:{id:'ev01',family:'family-water-01',label:'บันทึกสังเกตตัวอย่าง A',note:'ข้อมูลที่เขียนขึ้นสำหรับทดลองหน้าจอ ไม่มีภาพเหตุการณ์จริง',origin:'ต้นทางสมมติ: มิน'}},
{id:'v02',roomId:'canal-demo',name:'ฝน',kind:'observation',time:'17:27',text:'แชร์บันทึกของมินมาให้อ่านค่ะ ฉันไม่ได้อยู่ตรงนั้น ข้อมูลนี้จึงยังเป็นต้นทางเดียวกับโพสต์แรก',evidence:{id:'ev02',family:'family-water-01',label:'สำเนาบันทึกตัวอย่าง A',note:'ใช้กลุ่มต้นทางเดียวกับ ev01 ไม่ใช่หลักฐานอิสระเพิ่ม',origin:'สำเนาจาก ev01'}},
{id:'v03',roomId:'canal-demo',name:'นนท์',kind:'observation',time:'17:35',text:'ในโจทย์จำลอง เวลา 17:35 ผมเห็นแนวกั้นบริเวณสะพาน A และรายงานว่าทุกช่องทางผ่านไม่ได้',evidence:{id:'ev03',family:'family-bridge-01',label:'บันทึกตัวอย่างฝั่งสนับสนุน',note:'เป็น fixture สำหรับทดสอบการแสดงข้ออ้างที่มีหลักฐานขัดกัน',origin:'ต้นทางสมมติ: นนท์'}},
{id:'v04',roomId:'canal-demo',name:'เมย์',kind:'correction',time:'17:36',text:'ข้อมูลที่ฉันเห็นในโจทย์ต่างออกไปค่ะ เวลา 17:35 บริเวณสะพาน A ยังมีรถผ่านช่องขวา จึงอาจไม่ใช่ทุกช่องทาง',evidence:{id:'ev04',family:'family-bridge-02',label:'บันทึกตัวอย่างฝั่งคัดค้าน',note:'ตัวอย่างที่คัดค้าน Claim เดียวกันและเวลาเดียวกัน ต้องเก็บให้เห็นทั้งสองด้าน',origin:'ต้นทางสมมติ: เมย์'}},
{id:'v05',roomId:'canal-demo',name:'ป่าน',kind:'question',time:'17:39',text:'มีข้อมูลของถนนอีกฝั่งบ้างไหมคะ? ข้อมูลหน้าตลาดอาจใช้ตอบเรื่องอีกฝั่งไม่ได้'},
{id:'v06',roomId:'canal-demo',name:'ต้น',kind:'opinion',time:'17:42',text:'ชอบที่แยกแต่ละจุดครับ จะได้ไม่เข้าใจว่ารายงานจุดเดียวหมายถึงทั้งย่าน'},
{id:'v07',roomId:'mobile-ai-demo',name:'ภพ',kind:'observation',time:'16:30',text:'ผลทดสอบจำลองชุด A: ปิดอินเทอร์เน็ตแล้วผู้ช่วยยังตอบข้อความได้ ทดสอบเฉพาะอุปกรณ์ A เท่านั้น',evidence:{id:'ev07',family:'family-lab-01',label:'ผลทดสอบสมมติชุด A',note:'ไม่ได้ทดสอบโมเดลหรือโทรศัพท์จริง ตัวเลขและความสามารถไม่ได้ใช้อ้างอิงผลิตภัณฑ์',origin:'ห้องทดลองสมมติ'}},
{id:'v08',roomId:'mobile-ai-demo',name:'ออม',kind:'question',time:'16:38',text:'ถ้าเปิดนาน ๆ การใช้แบตเป็นอย่างไร? ในบันทึกนี้ยังไม่มีข้อมูลส่วนนี้'},
{id:'v09',roomId:'mobile-ai-demo',name:'เจ',kind:'opinion',time:'16:45',text:'ส่วนตัวสนใจการทำงานโดยไม่ส่งข้อความออกนอกเครื่อง มากกว่าความเร็วอย่างเดียว'},
{id:'v10',roomId:'mobile-ai-demo',name:'นิด',kind:'correction',time:'16:55',text:'ควรระบุว่าทดสอบกับอุปกรณ์ A เท่านั้นค่ะ ยังนำไปสรุปว่าทำงานได้กับทุกเครื่องไม่ได้'},
{id:'v11',roomId:'bus-demo',name:'กาย',kind:'observation',time:'16:20',text:'ในสถานการณ์จำลองพบป้ายจุดรับชั่วคราวหน้าสวน A แต่ป้ายที่เห็นไม่มีเวลาสิ้นสุด',evidence:{id:'ev11',family:'family-bus-01',label:'รายละเอียดป้ายสมมติ',note:'ไม่มีป้ายหรือประกาศจากผู้ให้บริการจริง ห้ามใช้เพื่อวางแผนเดินทาง',origin:'บันทึกสมมติของกาย'}},
{id:'v12',roomId:'bus-demo',name:'บี',kind:'question',time:'16:30',text:'รถกลับมาใช้จุดเดิมเมื่อไรครับ ยังไม่เห็นกำหนดในข้อมูลนี้'},
{id:'v13',roomId:'bus-demo',name:'แพร',kind:'opinion',time:'16:34',text:'น่าจะมีแผนผังแสดงทั้งจุดเก่าและจุดใหม่ให้อ่านง่ายขึ้น'},
{id:'v14',roomId:'bus-demo',name:'ภู',kind:'correction',time:'16:40',text:'คำว่าเปลี่ยนจุดรับยังไม่ใช่ยกเลิกเส้นทางนะครับ ควรแยกสองเรื่องนี้'},
{id:'v15',roomId:'garden-demo',name:'ใบ',kind:'observation',time:'15:20',text:'ในกิจกรรมสมมติมีโต๊ะแบ่งต้นไม้ที่ลาน A และมีผู้ร่วมกิจกรรมนำกระถางของตัวเองมา',evidence:{id:'ev15',family:'family-garden-01',label:'บันทึกกิจกรรมตัวอย่าง',note:'กิจกรรมนี้สร้างขึ้นเพื่อสาธิต Echo Voice Room',origin:'ผู้ร่วมกิจกรรมสมมติ'}},
{id:'v16',roomId:'garden-demo',name:'ส้ม',kind:'opinion',time:'15:40',text:'อยากให้มีมุมสอนปลูกสำหรับคนเริ่มต้นด้วยค่ะ จะได้กลับไปดูแลต้นไม้ต่อได้'},
{id:'v17',roomId:'garden-demo',name:'นัท',kind:'question',time:'15:50',text:'รอบถัดไปจัดวันไหน และต้องลงทะเบียนหรือเปล่า?'}
];
