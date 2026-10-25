/* Shared bounds for local QR image imports. Never sends image data to the server. */
(() => {
    const MAX_BYTES=20*1024*1024, MAX_PIXELS=40_000_000, MAX_DIMENSION=1600;
    function limit(message){return Object.assign(new Error(message),{code:"QR_IMAGE_LIMIT"});}
    function validate(width,height){
        if(!Number.isFinite(width)||!Number.isFinite(height)||width<1||height<1||width*height>MAX_PIXELS)
            throw limit("Choose an image smaller than 40 megapixels.");
    }
    function orientation(bytes,start,end){
        const view=new DataView(bytes.buffer),little=bytes[start]===73&&bytes[start+1]===73;
        if(start+8>end || !little && !(bytes[start]===77&&bytes[start+1]===77))return 1;
        if(view.getUint16(start+2,little)!==42)return 1;
        const directory=start+view.getUint32(start+4,little);
        if(directory<start || directory+2>end)return 1;
        const count=Math.min(view.getUint16(directory,little),512);
        for(let i=0;i<count;i++){
            const entry=directory+2+i*12;if(entry+12>end)break;
            if(view.getUint16(entry,little)===274&&view.getUint16(entry+2,little)===3&&view.getUint32(entry+4,little)===1){
                const value=view.getUint16(entry+8,little);return value>=1&&value<=8?value:1;
            }
        }
        return 1;
    }
    function oriented(size,value){return value>=5?[size[1],size[0]]:size;}
    async function dimensions(file){
        if(!file.slice)return null;
        const bytes=new Uint8Array(await file.slice(0,262144).arrayBuffer()),view=new DataView(bytes.buffer);
        const ascii=(offset,length)=>String.fromCharCode(...bytes.slice(offset,offset+length));
        if(bytes.length>=24&&ascii(1,3)==="PNG"&&view.getUint32(0)===0x89504e47){
            const size=[view.getUint32(16),view.getUint32(20)];let offset=8;
            while(offset+8<=bytes.length){
                const length=view.getUint32(offset),end=offset+8+length;
                if(end+4>bytes.length){size.resizeSafe=false;break;}
                const kind=ascii(offset+4,4);
                if(kind==="eXIf")return oriented(size,orientation(bytes,offset+8,end));
                if(kind==="IEND")break;
                offset=end+4;
            }
            return size;
        }
        if(bytes.length>=10&&ascii(0,3)==="GIF")return [view.getUint16(6,true),view.getUint16(8,true)];
        if(bytes.length>=26&&ascii(0,2)==="BM")return view.getUint32(14,true)===12?[view.getUint16(18,true),view.getUint16(20,true)]:[Math.abs(view.getInt32(18,true)),Math.abs(view.getInt32(22,true))];
        if(bytes.length>=30&&ascii(0,4)==="RIFF"&&ascii(8,4)==="WEBP"){
            const kind=ascii(12,4);
            if(kind==="VP8X"){
                const size=[1+bytes[24]+(bytes[25]<<8)+(bytes[26]<<16),1+bytes[27]+(bytes[28]<<8)+(bytes[29]<<16)];
                if(bytes[20]&8)size.resizeSafe=false; // EXIF can follow compressed data outside the bounded header.
                return size;
            }
            if(kind==="VP8 "&&bytes[23]===0x9d&&bytes[24]===1&&bytes[25]===0x2a)return [view.getUint16(26,true)&16383,view.getUint16(28,true)&16383];
            if(kind==="VP8L"&&bytes[20]===0x2f)return [1+bytes[21]+((bytes[22]&63)<<8),1+(bytes[22]>>6)+(bytes[23]<<2)+((bytes[24]&15)<<10)];
        }
        if(bytes.length>=4&&bytes[0]===255&&bytes[1]===216){
            let offset=2,size=null,rotation=1;
            while(offset+4<=bytes.length){
                if(bytes[offset++]!==255)break;
                while(bytes[offset]===255)offset++;
                const marker=bytes[offset++];
                if(marker===217||marker===218)break;
                if(marker===1||marker>=208&&marker<=215)continue;
                if(offset+2>bytes.length)break;
                const length=view.getUint16(offset);
                if(length<2||offset+length>bytes.length)break;
                if(marker===225&&length>=16&&ascii(offset+2,6)==="Exif\0\0")rotation=orientation(bytes,offset+8,offset+length);
                if([192,193,194,195,197,198,199,201,202,203,205,206,207].includes(marker)&&length>=7)
                    size=[view.getUint16(offset+5),view.getUint16(offset+3)];
                offset+=length;
            }
            if(size)return oriented(size,rotation);
        }
        return null;
    }
    async function load(file){
        if(file.size>MAX_BYTES)throw limit("Choose an image smaller than 20 MB.");
        const size=await dimensions(file);
        if(size)validate(...size);
        if(typeof createImageBitmap==="function"){
            let bitmap;
            try{
                const scale=size&&size.resizeSafe!==false?Math.min(1,MAX_DIMENSION/Math.max(...size)):1;
                const options={imageOrientation:"from-image",...(size&&scale<1?{resizeWidth:Math.max(1,Math.round(size[0]*scale)),resizeHeight:Math.max(1,Math.round(size[1]*scale)),resizeQuality:"high"}:{})};
                bitmap=await createImageBitmap(file,options);validate(bitmap.width,bitmap.height);
                return {source:bitmap,close:()=>bitmap.close()};
            }catch(error){bitmap?.close();if(error.code==="QR_IMAGE_LIMIT")throw error;}
        }
        const url=URL.createObjectURL(file),image=new Image();let timer;
        try{
            await new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(new Error("This image took too long to load.")),15000);image.onload=resolve;image.onerror=()=>reject(new Error("This image could not be read."));image.src=url;});
            validate(image.naturalWidth,image.naturalHeight);
            return {source:image,close:()=>{image.src="";URL.revokeObjectURL(url);}};
        }catch(error){image.src="";URL.revokeObjectURL(url);throw error;}
        finally{clearTimeout(timer);}
    }
    globalThis.LockstepImages=Object.freeze({load});
})();
