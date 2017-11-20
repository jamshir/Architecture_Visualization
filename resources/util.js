//function to read CSV file from given path
function readFile(filePath){
    var filePath = filePath;
    xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET",filePath,false);
    xmlhttp.send(null);
    var fileContent = xmlhttp.responseText;
    console.log(fileContent);
    return fileContent;
}

//this method returns an array of the names of components
async function visualize(fileName){
	var parsedJson = '{"name": "Android", "children": [';
	var parsedXML;
	var appNames, components;
	var fileNames = [];
	
	//fetch the names of all the XML files by checking the package names in the CSV file
	d3.csv("../data/domain-explicit-communication-1.csv", function(data){
		for(var i=0; i<data.length; i++){
			if(fileNames.indexOf(data[i].Package) == -1) fileNames.push(data[i].Package);
		}
	});

	await new Promise(resolve => setTimeout(resolve, 10));

	//create the JSON string
	var tempString = "";
	for(var x=0; x<fileNames.length; x++){

		d3.xml("../data/app-" + fileNames[x] + ".xml", function(data){
			appNames = data.documentElement.getElementsByTagName("name");
			components = data.documentElement.getElementsByTagName("compName");
		});
		console.log(appNames);
		await new Promise(resolve => setTimeout(resolve, 10));
		
		//for(var i=0; i<appNames.length; i++){
		tempString = tempString + '{"name": "' + appNames[0].innerHTML + '","children": [';
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

	drawCirclePacking(parsedJson);
}

//this method draws the visualisation
function drawCirclePacking(parsedJson){

    var root = JSON.parse(parsedJson);
    root = d3.hierarchy(root)
        .sum(function(d) { return d.size; })
        .sort(function(a, b) { return b.value - a.value; });

    var focus = root,
        nodes = pack(root).descendants(),
        view;

    var circle = g.selectAll("circle")
      .data(nodes)
      .enter().append("circle")
        .attr("class", function(d) { return d.parent ? d.children ? "node" : "node node--leaf" : "node node--root"; })
        .style("fill", function(d) { return d.children ? color(d.depth) : null; })
        .on("click", function(d) { if (focus !== d) zoom(d), d3.event.stopPropagation(); });

    var text = g.selectAll("text")
      .data(nodes)
      .enter().append("text")
        .attr("class", "label")
        .style("fill-opacity", function(d) { return d.parent === root ? 1 : 0; })
        .style("display", function(d) { return d.parent === root ? "inline" : "none"; })
        .text(function(d) { return d.data.name; });

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
      node.attr("transform", function(d) { return "translate(" + (d.x - v[0]) * k + "," + (d.y - v[1]) * k + ")"; });
      circle.attr("r", function(d) { return d.r * k; });
    }

}
