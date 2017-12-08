
	var remaining = 0;
	var collection = [];
	var data;

	var appName = ""; 
	var visualizationOption = "privilege"; 
	var coname = sessionStorage.getItem("coname");
	var paname = sessionStorage.getItem("paname");
	var sarg= coname;
	var parg = paname;
	//console.log(coname); // full name
	//console.log(a);
	//console.log(paname); // only app name, not package name
	$(document).ready(concatCSVs(visualizationOption));

	function showPrivilegeEscalation()
	{
		d3.selectAll("svg").remove();
		d3.select("#vulnerability").remove();
		d3.select("#vul").append("span").attr("id", "vulnerability").attr("class", "attack");
		d3.select("#vul").text("Privilege Escalation");
		visualizationOption = "privilege";
		concatCSVs(visualizationOption);
	}

	function showIntentSpoofing()
	{
		d3.selectAll("svg").remove();
		d3.select("#vulnerability").remove();
		d3.select("#vul").append("span").attr("id", "vulnerability").attr("class", "attack");
		d3.select("#vul").text("Intent Spoofing Attack");
		visualizationOption = "spoofing";
		concatCSVs(visualizationOption);
	}

	function showUnauthorizedIntent()
	{
		d3.selectAll("svg").remove();
		d3.select("#vulnerability").remove();
		d3.select("#vul").append("span").attr("id", "vulnerability").attr("class", "attack");
		d3.select("#vul").text("Unauthorized Intent Reciept");
		visualizationOption = "unauthrcpt";
		concatCSVs(visualizationOption);
	} 


	function concatCSVs(visualizationOption){
	  var uris = ['../data/domain-explicit-communication-5.csv','../data/domain-implicit-communication-5.csv','../data/domain-permission-enforcement-5.csv','../data/domain-permission-granted-5.csv','../data/domain-permission-usage-5.csv'];
	 //var uris = ['data//domain-explicit-communication-5.csv'];
	  remaining = uris.length;
	  uris.forEach(function(uri){

	    getCSV(uri, collector, visualizationOption)
	  })
	}

	function getCSV(uri, callback, visualizationOption){
	  $.ajax(uri, {
	    success: function(response)  
	   {

	 	data = $.csv.toArrays(response);
	// 	console.log(data);
	 	generategraph(data,uri,sarg,parg,visualizationOption);
	   }   
	  })
	}

	function collector(data){
	  if(remaining == 0){
	    throw new Error('Got more results than expected')
	  }
	  remaining -= 1;
	  collection.push(data);
	  
	}



	function generategraph(data,uri,sarg,parg,visualizationOption){
		

		var w = 1020, h = 720;
	      var labelDistance = 0;

	      var vis = d3.select("body").append("svg:svg").attr("width", w).attr("height", h).style("border-style", "solid").style("border-width", "2px").style("float","right");
	      
	      var nodes = [];
	      var labelAnchors = [];
	      var labelAnchorLinks = [];
	      var links = [];
	      var nodenames = [];
	      var mainnodes = [];
	      var sys = [];
	      var ind;
	      var mcount = 0;
	      var ccount=0;
		  var rcount=0;
		  var l1=0;
		  var l2=0;
		 	for(var row in data)
			{
				rcount++;
				ccount=0;
					for(var item in data[row])
					{
						ccount++;
					}
			}
		   var sourceappname;
		   var targetappname;
		   var id =0;
		   var comp2;
		  for (var i = 0; i < rcount; i++) 
		  {
		  		if(data[i][1].valueOf() == sarg)
		  		{
		  			ind = i;
		  			paname = paname.replace(/ /g,'')

		  			var re = new RegExp(paname, "i");
		  			//console.log(re);
		  			if(data[i][0].match(re))
					{//check the appname which is sent from application view code
		  				sourceappname = data[i][0];// here, app name is package name
		  				 var indx = sourceappname.lastIndexOf(".");
	          				if(indx!=-1)
	            				comp2 = sourceappname.substring(indx+1, sourceappname.length);
	            			else if(indx == -1)
	            				comp2 = sourceappname;
		  				//sourceappname = paname;
		  				//console.log(sourceappname);
		  				id = data[i][2];
		  				break;
		  			}
		  			else
		  			{
		  				sourceappname = data[i][0];
		  				var indx = sourceappname.lastIndexOf(".");
	          				if(indx!=-1)
	            				comp2 = sourceappname.substring(indx+1, sourceappname.length);
	            			else if(indx == -1)
	            				comp2 = sourceappname;
		  				id = data[i][2];
		  				//console.log(comp2);
		  			}

		  		}
		  }

	        
		  xmlhttp = new XMLHttpRequest();
	      xmlhttp.open("GET","../data/analysisResults-5.xml",false);
	      xmlhttp.send();
	      xmlDoc = xmlhttp.responseXML;

	      var len;
	      var smal = [];
	      var tmal = [];
	      var smal1 = [];
	      var tempInstncs;
	      //var malComps = [], vulComps = [];

	      //app view conditions to check for specific analysis - privilege, spoofing and unauthorized intent
	      if(visualizationOption == "privilege"){
	      	//TODO initialize len depending on the number of malcomp and vulcomp's in privilege escalation
	      	var privInstncs = xmlDoc.getElementsByTagName("privilegeEscalationInstance");
	      	len = privInstncs.length;
			tempInstncs = privInstncs;
	      }
	      else if(visualizationOption == "spoofing"){
	      	//TODO initialize len depending on the number of malcomp and vulcomp's in spoofing
	      	var spoofInstncs = xmlDoc.getElementsByTagName("intentSpoofingInstance");
	      	len = spoofInstncs.length;
	      	tempInstncs = spoofInstncs;
	      }
		  else if(visualizationOption == "unauthrcpt"){
	      	//TODO initialize len depending on the number of malcomp and vulcomp's in unauthrcpt
			var unauthInstncs = xmlDoc.getElementsByTagName("unauthorizedIntentReceiptInstance");
			len = unauthInstncs.length;
			tempInstncs = unauthInstncs;
	      }

	      for(var i=0;i<=len-1; i++)
	          smal[i] = tempInstncs[i].children[1].innerHTML;   
	//      console.log(smal);
	      for(var i=0;i<=len-1; i++)
	          tmal[i] = tempInstncs[i].children[5].innerHTML;


	     // console.log(smal);
	      //console.log(tmal);
		var lab = sarg + "(" + sourceappname + ")"; 
		 var indx = sarg.lastIndexOf(".");
		 var comp1;
	          if(indx!=-1)
	            comp1 = sarg.substring(indx+1, sarg.length);
	          else if(indx == -1)
	            comp1 = sarg;
	       

	     comp1 = comp1 + "(" + comp2 + ")";  
			for(var i =0; i<smal.length;i++)
			{
				if(sarg.valueOf() == smal[i].valueOf())
				{
					if(lab.match(/\[M\]/g))
					{
						break;
					}
					lab = lab + "[M]";
					//console.log(lab);

					if(comp1.match(/\[M\]/g))
					{
						break;
					}
					
					comp1 = comp1 + "[M]";
				}
			}
			for(var i =0; i<tmal.length;i++)
			{
				if(sarg.valueOf() == tmal[i].valueOf())
				{
					if(lab.match(/\[V\]/g))
					{
						break;
					}
					lab = lab + "[V]";
					if(comp1.match(/\[V\]/g))
					{
						break;
					}
					
					comp1 = comp1 + "[V]";
				}
			}

	       var node = {  // this is for sarg
	          //label : nodenames[i]
	          label : comp1 
	        };
	        nodes.push(node);
	        labelAnchors.push({
	          node : node
	        });
	        labelAnchors.push({
	          node : node
	        });	
	      
				var cou=0;
				var q=0;
				
				//console.log(rcount);
				var sou = 0;
				var tar = 0;
					
				for(var a=0; a<nodes.length;a++)
				{
					if(comp1.valueOf() == nodes[a].label.valueOf())
					{
						sou = a;
						//console.log(a);
						break;
					}
				}


				var t;
				var lab2;
				for(var j = 0; j < ccount; j++)
				{
					//console.log("y");
					if(data[ind][j] == 1)
					{
						//console.log("e");
						if(j == 2)
						{
							continue;
						}



						//var s= sarg;
						var x = data[0][j];
						if((uri.match(/permission/)))
						{		//console.log("y");
								
								var node = {
	          					label : x.valueOf()
	        					};
	        					nodes.push(node);
	        					labelAnchors.push({
	         			 		node : node
	        					});
	        					labelAnchors.push({
	          					node : node
	        					});
	        				

							for(var a=0; a<nodes.length;a++)
									{

										if(x.valueOf() == nodes[a].label.valueOf())
										{
											tar = a;
											links.push({
														source : sou,
														target : tar,
														weight : Math.random()
													});
											break;
										
										}
										else
										{
										//console.log("source false");
										}
									}
						}
						else
						{	
							var comp3;
							var comp4;
							for(var k=0; k<rcount;k++)
							{
								if(data[k][2] == x)
								{
								t = data[k][1];
								var indx = t.lastIndexOf(".");
	          					if(indx!=-1)
	            					comp3= t.substring(indx+1, t.length);
	            				else if(indx == -1)
	            					comp3 = t;
								targetappname = data[k][0];

								var indx2 = targetappname.lastIndexOf(".");
	          					if(indx2!=-1)
	            					comp4 = targetappname.substring(indx2+1, targetappname.length);
	            				else if(indx2 == -1)
	            					comp4 = targetappname;
	            				comp3 = comp3 + "(" + comp4 + ")";
								lab2 = t.valueOf() + "(" + targetappname + ")"; 							
								
								
								for(var i =0; i<smal.length;i++)
								{
									if(t.valueOf() == smal[i].valueOf())
									{
										if(lab2.match(/\[M\]/g))
										{
											break;
										}

										lab2 = lab2 + "[M]";
										if(comp3.match(/\[M\]/g))
										{
											break;
										}
										comp3 = comp3 + "[M]";
									}
								}
								for (var i = 0; i < tmal.length; i++) 
								{
									if(t.valueOf() == tmal[i].valueOf())
									{
										if(lab2.match(/\[V\]/g))
										{
											break;
										}
										lab2 = lab2 + "[V]";
										if(comp3.match(/\[V\]/g))
										{
											break;
										}
										comp3 = comp3 + "[V]";
									}
								}
								var node = {
	          					label : comp3
	        					};
	        					nodes.push(node);
	        					labelAnchors.push({
	         			 		node : node
	        					});
	        					labelAnchors.push({
	          					node : node
	        					});
	        					//console.log(comp3);
	        					//var find = t.valueOf() + "(" + targetappname + ")"; 
								for(var b=0 ;b<nodes.length;b++)
								{
									if(comp3 == nodes[b].label.valueOf())
									{
										tar=b;
										links.push({
										source : sou,
										target : tar,
										weight : Math.random()
										});
										break;
												
									}
								}

								}

							}
						}

							
						

					}
					
				}

						

					var sou1 = 0;
					var tar1 = 0;	
					var sourceappname1;
					var targetappname1;
					lab3 = 0;
					var set = 0;
					var comp5;
					var comp6;
					var colid = parseInt(id.valueOf()) + 3; // column interaction for non permission files
					//console.log(colid);

					for(var i=0;i<rcount;i++)
					{	
						
						if(data[i][colid] == 1)
						{
							if(i == 0)
								continue;
							//console.log(data[i][1]);
							sourceappname1 = data[i][0];
							var indx = sourceappname1.lastIndexOf(".");
	          					if(indx!=-1)
	            					comp6= sourceappname1.substring(indx+1, sourceappname1.length);
	            				else if(indx == -1)
	            					comp6 = sourceappname1;
	            			var temp = data[i][1];
	            			var indx2 = temp.lastIndexOf(".");
	          					if(indx2!=-1)
	            					comp5= temp.substring(indx2+1, temp.length);
	            				else if(indx2 == -1)
	            					comp5 = temp;

	            			comp5 = comp5 + "(" + comp6 + ")"; 			
							lab3 = data[i][1] + "(" + sourceappname1 + ")";
							//console.log(smal);
								
							
							for(var j =0; j<smal.length;j++)
								{

									if(temp.valueOf() == smal[j].valueOf())
									{
										if(lab3.match(/\[M\]/g))
										{
											break;
										}
										lab3 = lab3 + "[M]";
										if(comp5.match(/\[M\]/g))
										{
											break;
										}
										comp5 = comp5 + "[M]";
									}
									else
									{
										//console.log("ssup");
									}
								}
								for (var j = 0; j < tmal.length; j++) 
								{
									if(data[i][1].valueOf() == tmal[j].valueOf())
									{
										if(lab3.match(/\[V\]/g))
										{
											break;
										}
										lab3 = lab3 + "[V]";
										if(comp5.match(/\[V\]/g))
										{
											break;
										}
										comp5 = comp5 + "[V]";
									}
									else
									{
										//console.log("ssup1");
									}
								}
								

							
							for(var j =0; j<nodes.length;j++)
							{
								if(comp5.valueOf() == nodes[j].label.valueOf())
								{
									
									set = 1;
									break;

								}
							}
							if(set == 0)
							{
								//console.log("duplicate");
		
								var node = {
	          					//label : data[i][1]
	          					label : comp5
	        					};
	        					nodes.push(node);
	        					labelAnchors.push({
	         			 		node : node
	        					});
	        					labelAnchors.push({
	          					node : node
	        					});
	        					
							}
							else
							{
								//console.log(set);
							}
							
	        					//console.log(nodes);
	        					for(var a=0; a<nodes.length;a++)
								{
									//if(data[i][1].valueOf() == nodes[a].label.valueOf())
									if(comp5.valueOf() == nodes[a].label.valueOf())
									{
										sou1 = a;
										//console.log(a);
										break;
									}
									else
									{
										//console.log("source false");
									}
								}

	        					



	        					for(var a=0; a<nodes.length;a++)
								{
									if(comp1.valueOf() == nodes[a].label.valueOf())
									{
										tar1 = a;
										//console.log(a);
										links.push({
										source : sou1,
										target : tar1,
										weight : Math.random()
										});
										break;
									}
									else
									{
										//console.log("target false");
									}
								}
						}
					}

					

					for(q=0; q <nodes.length; q++){

						labelAnchorLinks.push({
									source : q * 2,
									target : q * 2 + 1,
									weight : Math.random()
								});

						}
					
					
			//console.log(nodes);			
							
				function getRandomColor() 
				{
	  				
	  				if(uri.match(/explicit/))
	  				{
	  					color = '#D5DBDB';
	  				}
	  				else if(uri.match(/implicit/))
	  				{
	  					color = '#00BFFF';
	  				}
	  				else if(uri.match(/enforcement/))
	  				{
	  					color = '#FF0000';
	  				}
	  				else if(uri.match(/granted/))
	  				{
	  					color = '#00FF00';
	  				}
	  				else if(uri.match(/usage/))
	  				{
	  					color = '#EE82EE';
	  				}
	  			return color;
					}

		vis.append("svg:defs").selectAll("marker")
	    //.data(["end"])
	    .data(["end"])      // Different link/path types can be defined here
	  .enter().append("svg:marker")    // This section adds in the arrows
	    .attr("id", String)
	    .attr("viewBox", "0 -5 10 10")
	    .attr("refX", 15)
	    .attr("refY", -1.5)
	    .attr("markerWidth", 5)
	    .attr("markerHeight", 5)
	    .attr("orient", "auto-start-reverse")
	    .append("svg:path")	
	    .attr("d", "M0,-5L10,0L0,5");

					//console.log(links);
				var force = d3.layout.force().size([w, h]).nodes(nodes).links(links).gravity(1).linkDistance(250).charge(-3000).linkStrength(function(x) {
					return x.weight * 10
				});


				force.start();

				var force2 = d3.layout.force().nodes(labelAnchors).links(labelAnchorLinks).gravity(0).linkDistance(0).linkStrength(8).charge(-100).size([w, h]);
				force2.start();

				//var link = vis.selectAll("line.link").data(links).enter().append("svg:line").attr("class", "link").style("stroke", "#D35400");

				var link = vis.selectAll("line.link").data(links).enter().append("svg:line").attr("class", "link").style("stroke", function(d){
					//console.log(d);
					//console.log(d.source.label);
					//console.log(d.target.label);
					if((d.source.label.match(/\[M\]/g) && d.target.label.match(/\[V\]/g)) || (d.target.label.match(/\[M\]/g) && d.source.label.match(/\[V\]/g)) )
					{
						//console.log(d.source.label);
						return "#000000";
					}
					else
					{
						return "#a9a9a9";		
					}
					
				})
				.style("stroke-width",function(d){
					if((d.source.label.match(/\[M\]/g) && d.target.label.match(/\[V\]/g)) || (d.target.label.match(/\[M\]/g) && d.source.label.match(/\[V\]/g)))
					{
						return 4;
					}
					else
					{
						return 4;
					}
				})
				//.attr("marker-start", "url(#start)");
				.attr("marker-end", "url(#end)");
				

				var node = vis.selectAll("g.node").data(force.nodes()).enter().append("svg:g").attr("class", "node");
				node.append("svg:circle").attr("r", 15).style("fill",getRandomColor()).style("stroke", "#FFF").style("stroke-width", 3);
				
				node.call(force.drag); // force.drag( node ); same thing https://stackoverflow.com/questions/22871257/understanding-call-in-d3-js-with-force-directed-layouts


				var anchorLink = vis.selectAll("line.anchorLink").data(labelAnchorLinks).enter().append("svg:line").attr("class", "anchorLink").style("stroke", "#000000");

				var anchorNode = vis.selectAll("g.anchorNode").data(force2.nodes()).enter().append("svg:g").attr("class", "anchorNode");
				anchorNode.append("svg:circle").attr("r", 0).style("fill", "#00000");
				anchorNode.append("svg:text").text(function(d, i) {
					return i % 2 == 0 ? "" : d.node.label
				}).style("fill", "#555")
					.style("font-family", function(d){return "Open Sans"})
					.style("font-size", 24);
					
				//code to reset the font-weight depending on the option chosen
				if(visualizationOption == "privilege"){
				anchorNode.style("font-weight", function(d) { 
						//console.log(d.node.label.match(/(M)/));
						if(d.node.label.match(/\[M\]/g) || d.node.label.match(/\[V\]/g) )
						{
							return "bold";
						}
						else
						{
							return "200";
						}	
					});
				}	

				if(visualizationOption == "spoofing"){
				anchorNode.style("font-weight", function(d) { 
						//console.log(d.node.label.match(/(M)/));
						if(d.node.label.match(/\[M\]/g) || d.node.label.match(/\[V\]/g) )
						{
							return "bold";
						}
						else
						{
							return "200";
						}	
					});
				}

				if(visualizationOption == "unauthrcpt"){
				anchorNode.style("font-weight", function(d) { 
						//console.log(d.node.label.match(/(M)/));
						if(d.node.label.match(/\[M\]/g) || d.node.label.match(/\[V\]/g) )
						{
							return "bold";
						}
						else
						{
							return "200";
						}	
					});
				}
		
					
				var updateLink = function() {
					this.attr("x1", function(d) {
						return d.source.x;
					}).attr("y1", function(d) {
						return d.source.y;
					}).attr("x2", function(d) {
						return d.target.x;
					}).attr("y2", function(d) {
						return d.target.y;
					});

				}

				var updateNode = function() {
					this.attr("transform", function(d) {
						return "translate(" + d.x + "," + d.y + ")";
					});

				}


				force.on("tick", function() {

					force2.start();

					node.call(updateNode);

					anchorNode.each(function(d, i) {
					if(i % 2 == 0) { // i%2 == 0 means that both anchor node and node are in the same location. node has not changed position
							d.x = d.node.x;
							d.y = d.node.y;
						} else {
							var b = this.childNodes[1].getBBox();

							var diffX = d.x - d.node.x;
							var diffY = d.y - d.node.y;

							var dist = Math.sqrt(diffX * diffX + diffY * diffY);

							var shiftX = b.width * (diffX - dist) / (dist * 2);
							shiftX = Math.max(-b.width, Math.min(0, shiftX));
							var shiftY = 5;
							this.childNodes[1].setAttribute("transform", "translate(" + shiftX + "," + shiftY + ")");
						}
					});


					anchorNode.call(updateNode);

					link.call(updateLink);
					anchorLink.call(updateLink);

				});

	}
