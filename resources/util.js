  var systemNumber;//TODO make dynamic from the input screen
  var jsonFinal;
  var changedColorIdsApps = [], changedColorIdsComps = [];
  //function to read CSV file from given path
  function readFile(filePath){
      var filePath = filePath;
      xmlhttp = new XMLHttpRequest();
      xmlhttp.open("GET",filePath,false);
      xmlhttp.send(null);
      var fileContent = xmlhttp.responseText;
      return fileContent;
  }

  //this method returns an array of the names of components
  async function visualize(fileName){
  	var parsedJson = '{"name": "Android", "children": [';
  	var parsedXML;
  	var appNames, components, comps;
  	var fileNames = [];
    var packname;
  	systemNumber = sessionStorage.getItem("sysnum");

  	//fetch the names of all the XML files by checking the package names in the CSV file
  	d3.csv("../data/domain-explicit-communication-" + systemNumber + ".csv", function(data){
  		for(var i=0; i<data.length; i++){
  			if(fileNames.indexOf(data[i].Package) == -1) fileNames.push(data[i].Package);
  		}
  	});

  	await new Promise(resolve => setTimeout(resolve, 100));

  	//create the JSON string
  	var tempString = "";
  	for(var x=0; x<fileNames.length; x++){

  		d3.xml("../data/app-" + fileNames[x] + ".xml", function(data){
  			appNames = data.documentElement.getElementsByTagName("name");
  			components = data.documentElement.getElementsByTagName("fullName");
        packname = data.documentElement.getElementsByTagName("packageName");
  		});


  		await new Promise(resolve => setTimeout(resolve, 100));


      //tempString = tempString + '{"name": "' + appNames[0].innerHTML + '","children": [';

      tempString = tempString + '{"name": "' + appNames[0].innerHTML + '", "fullName": "' + packname[0].innerHTML + '", "children": [';

  		for(var j=0; j<components.length; j++){
  			tempString = tempString + '{ "name": "' + components[j].innerHTML + '", "size": 1000}';
  			tempString = j<components.length-1 ? (tempString + ",") : tempString;
  		}
  		tempString = tempString + ']}';
  		//tempString = i<appNames.length-1 ? (tempString + ",") : tempString;
  		//}
  		tempString = x<fileNames.length-1 ? (tempString + ",") : tempString;
  	}		

  	await new Promise(resolve => setTimeout(resolve, 50));

  	parsedJson = parsedJson + tempString + "]}";
    jsonFinal = parsedJson;
  	drawCirclePacking(parsedJson, comps);
  }

  //this method draws the visualisation
  function drawCirclePacking(parsedJson, comps){
      var root = JSON.parse(parsedJson);
      root = d3.hierarchy(root)
          .sum(function(d) { return d.size; })
          .sort(function(a, b) { return b.value - a.value; });

      var focus = root, nodes = pack(root).descendants(), view;

      var circle = g.selectAll("circle")
        .data(nodes)
        .enter().append("circle")
          .attr("class", function(d) { return d.parent ? d.children ? "node" : "node node--leaf" : "node node--root"; })
          .attr("id", function(d, i){ 
                //if this is an app node, we give it an id equivalent to it's appname else we give it an id "nApp"
                if(d.depth === 1) return d.data.fullName;
                else if(d.depth === 2)
                {
                  console.log(d.data.name);
                  return d.data.name;
                } 
                else return "nApp";
           })
          .style("fill", function(d) {
            return d.children ? color(d.depth) : null; })
          .on("click", function(d) {
            //if this is the leaf node, simply call graphs view code
            //else have the if condition shown below

              	if(!d.children && focus !== d.parent) zoom(d.parent), d3.event.stopPropagation();
                else if(!d.children && focus === d.parent){
                  var cname = d.data.name;
                  var pname = d.parent.data.name;
                  if(pname !== "System"){
                    sessionStorage.setItem("coname", cname);
                    sessionStorage.setItem("paname", pname);
                    window.open("graphs.html");
                  }
                }
                else if (focus !== d) zoom(d),
              		d3.event.stopPropagation();
          	});

      var text = g.selectAll("text")
        .data(nodes)
        .enter().append("text")
          .attr("class", "label")
          .style("fill-opacity", function(d) { return d.parent === root ? 1 : 0; })
          .style("display", function(d) { return d.parent === root ? "inline" : "none"; })
          .style("word-wrap", "break-word")
          .style("font-weight", "bold")
          .text(function(d) { var text = d.data.name;
            var indx = text.lastIndexOf(".");
            if(indx!=-1)
              text = text.substring(indx+1, text.length);
            return text; });

      var node = g.selectAll("circle,text");

      svg.style("background", color(-1))
          .on("click", function() { zoom(root); });

      zoomTo([root.x, root.y, root.r * 2 + margin]);

      function zoom(d) {
        var focus0 = focus; focus = d;

        var transition = d3.transition()
            .duration(d3.event.altKey ? 7500 : 750)
            .tween("zoom", function(d) {
              var i = d3.interpolateZoom(view, [focus.x, focus.y, focus.r * 2 + margin]);
              return function(t) { zoomTo(i(t)); };
            });

        transition.selectAll("text")
          .filter(function(d) { return d.parent === focus || this.style.display === "inline"; })
            .style("fill-opacity", function(d) { return d.parent === focus ? 1 : 0; })
            .on("start", function(d) { if (d.parent === focus) this.style.display = "inline"; })
            .on("end", function(d) { if (d.parent !== focus) this.style.display = "none"; });
      }

      function zoomTo(v) {
        var k = diameter / v[2]; view = v;
        node.attr("transform", function(d) { 
          var transl = "translate(" + (d.x - v[0]) * k + "," + (d.y - v[1]) * k + ")"; 
        	return transl; });
        circle.attr("r", function(d) { return d.r*k; });
      }
  }

  //method to highlight the apps and components for Privilege Escalation vulnerability
  async function showPrivilegeEscalationApps()
  {
    resetColor();
    d3.select("#vulnerability").remove();
    d3.select("#vul").append("span").attr("id", "vulnerability").attr("class", "attack");
    d3.select("#vul").text("Privilege Escalation");

    changedColorIdsApps = [];
    var parsedJson = JSON.parse(jsonFinal);

    var maliciousApps = [], vulnerableApps = [], maliciousComponents = [], vulComponents = [];
    //parse the analysisresults file and find the apps that are malicious and vulnerable in prvlgescltn
    d3.xml("../data/analysisResults-" + systemNumber + ".xml", function(data){
      var privilegeEscalations = data.documentElement.getElementsByTagName("privilegeEscalationInstance");

      for(var i=0; i<privilegeEscalations.length; i++){
         var malappname = privilegeEscalations[i].children[0].innerHTML;
         var vulappname = privilegeEscalations[i].children[4].innerHTML;
         var malcomponent = privilegeEscalations[i].children[1].innerHTML;//fdsafds
         var vulcomponent = privilegeEscalations[i].children[5].innerHTML;//fdsafds
         if(maliciousApps.indexOf(malappname) == -1)
          maliciousApps.push(malappname);
         if(vulnerableApps.indexOf(vulappname) == -1)
          vulnerableApps.push(vulappname);
        //
        if(maliciousComponents.indexOf(malcomponent) == -1)
          maliciousComponents.push(malcomponent);
        if(vulComponents.indexOf(vulcomponent) == -1)
          vulComponents.push(vulcomponent);
        //fdsafdsa
      }
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    //change the color of the circles of the apps and components depending on whether they are malicious or vulnerable

    for(var i=0; i<maliciousApps.length; i++){
      // changecolor of matching appname with id from circle tags
      var id = "#" + maliciousApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "red");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<vulnerableApps.length; i++){
      // changecolor of matching appname with id from circle tags
      var id = "#" + vulnerableApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "DarkSlateBlue");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<maliciousComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + maliciousComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "orange");
      changedColorIdsComps.push(id);
    }
    for(var i=0; i<vulComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + vulComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "green");
      changedColorIdsComps.push(id);
    }
  }

  //method to highlight the apps and components for Intent Spoofing vulnerability
  async function showIntentSpoofingApps()
  {
    resetColor();
    d3.select("#vulnerability").remove();
    d3.select("#vul").append("span").attr("id", "vulnerability").attr("class", "attack");
    d3.select("#vul").text("Intent Spoofing");
    changedColorIdsApps = [];
    var parsedJson = JSON.parse(jsonFinal);

    var maliciousApps = [], vulnerableApps = [], maliciousComponents = [], vulComponents = [];
    //parse the analysisresults file and find the apps that are malicious and vulnerable in Intent spoofing
    d3.xml("../data/analysisResults-" + systemNumber + ".xml", function(data){
      var intentspoofs = data.documentElement.getElementsByTagName("intentSpoofingInstance");

      for(var i=0; i<intentspoofs.length; i++){
         var malappname = intentspoofs[i].children[0].innerHTML;
         var vulappname = intentspoofs[i].children[4].innerHTML;
         var malcomponent = intentspoofs[i].children[1].innerHTML;
         var vulcomponent = intentspoofs[i].children[5].innerHTML;
         if(maliciousApps.indexOf(malappname) == -1)
          maliciousApps.push(malappname);
         if(vulnerableApps.indexOf(vulappname) == -1)
          vulnerableApps.push(vulappname);
        if(maliciousComponents.indexOf(malcomponent) == -1)
          maliciousComponents.push(malcomponent);
        if(vulComponents.indexOf(vulcomponent) == -1)
          vulComponents.push(vulcomponent);
        //fdsafdsa
      }
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    //change the color of the circles of the apps depending on whether they are malicious (red) or vulnerable (blue)

    for(var i=0; i<maliciousApps.length; i++){
      // changecolor to red of matching appname with id from circle tags
      var id = "#" + maliciousApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "red");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<vulnerableApps.length; i++){
      // changecolor to blue of matching appname with id from circle tags
      var id = "#" + vulnerableApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "DarkSlateBlue");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<maliciousComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + maliciousComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "orange");
      changedColorIdsComps.push(id);
    }
    for(var i=0; i<vulComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + vulComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "green");
      changedColorIdsComps.push(id);
    }
  }

  //method to highlight the apps and components for Unathorized Intent Receipt vulnerability
  async function showUnauthorizedIntentApps()
  {
    resetColor();

    d3.select("#vulnerability").remove();
    d3.select("#vul").append("span").attr("id", "vulnerability");
    d3.select("#vul").text("Unauthorized Intent Receipt");
    changedColorIdsApps = [];
    var parsedJson = JSON.parse(jsonFinal);

    var maliciousApps = [], vulnerableApps = [], maliciousComponents = [], vulComponents = [];
    //parse the analysisresults file and find the apps that are malicious and vulnerable in Intent spoofing
    d3.xml("../data/analysisResults-" + systemNumber + ".xml", function(data){
      var unauthrecpts = data.documentElement.getElementsByTagName("unauthorizedIntentReceiptInstance");

      for(var i=0; i<unauthrecpts.length; i++){
         var malappname = unauthrecpts[i].children[0].innerHTML;
         var vulappname = unauthrecpts[i].children[4].innerHTML;
         var malcomponent = unauthrecpts[i].children[1].innerHTML;
         var vulcomponent = unauthrecpts[i].children[5].innerHTML;
         if(maliciousApps.indexOf(malappname) == -1)
          maliciousApps.push(malappname);
         if(vulnerableApps.indexOf(vulappname) == -1)
          vulnerableApps.push(vulappname);
        if(maliciousComponents.indexOf(malcomponent) == -1)
          maliciousComponents.push(malcomponent);
        if(vulComponents.indexOf(vulcomponent) == -1)
          vulComponents.push(vulcomponent);
        //fdsafdsa
      }
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    //change the color of the circles of the apps depending on whether they are malicious (red) or vulnerable (DarkSlateBlue)

    for(var i=0; i<maliciousApps.length; i++){
      // changecolor to red of matching appname with id from circle tags
      var id = "#" + maliciousApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "red");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<vulnerableApps.length; i++){
      // changecolor to blue of matching appname with id from circle tags
      var id = "#" + vulnerableApps[i];
      id = id.split('.').join('\\.');
      var appcircle = d3.select(String(id)).style("fill", "DarkSlateBlue");
      changedColorIdsApps.push(id);
    }
    for(var i=0; i<maliciousComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + maliciousComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "orange");
      changedColorIdsComps.push(id);
    }
    for(var i=0; i<vulComponents.length; i++){
      // changecolor of matching component name with id from circle tags
      var id = "#" + vulComponents[i];
      id = id.split('.').join('\\.');
      var compcircle = d3.selectAll(String(id)).style("fill", "green");
      changedColorIdsComps.push(id);
    }
  }

  //reset color method resets the colors of the visualization
  async function resetColor(){
    d3.select("#vul").text("");
    if(changedColorIdsApps.length != 0)
      for(var i = 0; i<changedColorIdsApps.length; i++){
        var resetAppColor = d3.select(changedColorIdsApps[i]).style("fill", color(1));
      }

  if(changedColorIdsComps.length != 0)
      for(var i = 0; i<changedColorIdsComps.length; i++){
        var resetAppColor = d3.selectAll(changedColorIdsComps[i]).style("fill", "white");
      }
  }