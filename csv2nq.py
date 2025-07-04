#!/usr/bin/python3

import argparse
import csv
import os
import json
from os.path import exists
import datetime
import collections

# Local imports
from nq import nqwriter

# The domain model can indicate if it supports recently introduced features by
# adding entries in DomainFeature.csv. Each feature has a reserved URI, and the
# definitive list is specified here.
# 
# To indicate domain model support for one of these features, DomainFeature.csv
# must have:
# - an entry with the URI matching the relevant URI specified here
# - the 'supported' field for that entry must be set to 'TRUE'
# 
# The 'supported' field provides a convenient way for domain modellers to switch
# some features off after they have been added.

# Domain model is designed to allow omission of dependent packages
HAS_OPTIONAL_PACKAGES = "feature#OptionalPackages"

# Domain model expects triples to be expanded
HAS_POPULATION_MODEL = "feature#PopulationModel"
# Strings appended to the average case to get min and max members of each population triplet
MIN_SUFFIX = "_Min"
MAX_SUFFIX = "_Max"

# Flags rather than naming conventions denote secondary and normal operational process threats
HAS_THREAT_TYPE_FLAGS = "feature#ThreatTypeFlags"

# Flags denote whether threats or control strategies should be used in current or future 
# risk calculations.
HAS_RISK_TYPE_FLAGS = "feature#RiskTypeFlags"

# Threats can have mixed causes (both TWAS and MS), which means SSM doesn't need to raise the
# likelihood of each MS to at least the level equivalent to the TW level of its TWAS.
HAS_MIXED_THREAT_CAUSES = "feature#MixedThreatCauses"

# Asset and relationship types are flagged if they are only used for system model construction 
# inference.
HAS_CONSTRUCTION_STATE = "feature#ConstructionStateFlags"

# Construction patterns form a partial sequence based on predecessor and successor relationships
# instead of having a specified priority (position) in a single construction sequence
HAS_CONSTRUCTION_DEPENDENCIES  = "feature#ConstructionDependencies"

# There is no feature for CSGs having optional controls because as fas as SSM is concerned 
# that is an optional feature.

# The second line of a CSV file often contains default values and if so will include domain#000000
DUMMY_URI = "domain#000000"

#
# Domain model graph URI, version info, label and description, plus feature list.
#
def output_domain_model(nqw, unfiltered, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Find out what features are supported
    if(exists("DomainFeature.csv")):
        with open("DomainFeature.csv", newline="") as csvfile:
            # Create the CSV reader object
            reader = csv.reader(csvfile)

            # Check that the table is as expected: if fields are missing this will raise an exception
            header = next(reader)
            uri_index = header.index("URI")
            comment_index = header.index("comment")
            supported_index = header.index("supported")

            for row in reader:
                # Skip the first line which contains default values for csvformat
                if DUMMY_URI in row: continue

                # Check if this row specifies whether the domain model supports for asset population triplet expansion
                if(row[uri_index] == HAS_POPULATION_MODEL and not raw.expanded):
                    print("Domain model specifies population support, but this was suppressed by the csv2nq command line")
                    supported = False
                else:
                    supported = row[supported_index].lower() == "true"

                # Write out the line if the feature is supported
                if(supported):
                    feature_list.append(row[uri_index])
                else:
                    print("Feature " + row[uri_index] + " is included but not supported")

            if(raw.expanded and HAS_POPULATION_MODEL not in feature_list):
                print("Population support was selected via the csv2nq command line, but is not supported by this domain model")

    # Then convert the domain model information
    with open("DomainModel.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)
        
        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        domainGraph_index = header.index("domainGraph")
        reasonerClass_index = header.index("reasonerClass")

        # Extract the information we need from the subsequent row
        row = next(reader)
        # Skip the first line which contains default values for csvformat
        if DUMMY_URI in row: row = next(reader)

        uri = "<{}>".format(row[uri_index])

        # Replace the last part of the provided domainGraph URI with the commandline argument if provided
        domainGraph = row[domainGraph_index] 
        if args["name"]:
            uri_frags = domainGraph.split("/")
            uri_frags[-1] = args["name"]
            domainGraph = "/".join(uri_frags)

        label = row[label_index]
        if args["label"]:
            label = args["label"]

        if (not raw.expanded and HAS_POPULATION_MODEL in feature_list):
            domainGraph = "<{}-unexpanded>".format(domainGraph)
            label = nqw.encode_string(label + "-UNEXPANDED")
            feature_list.remove(HAS_POPULATION_MODEL)
        else:
            domainGraph = "<{}>".format(domainGraph)
            label = nqw.encode_string(label)
        comment = nqw.encode_string(row[comment_index])

        versionInfo = args["version"]
        if (unfiltered):
            versionInfo += "-unfiltered"
        versionInfo = nqw.encode_string(versionInfo)
        
        reasonerClass = nqw.encode_string(row[reasonerClass_index])
        
        # Set NQ writer to the (pre-encoded) domain graph URI
        nqw.set_graph(domainGraph)
        
        # Output lines we need to the NQ file
        nqw.write_quad(uri, nqw.encode_owl_uri("owl#imports"), nqw.encode_ssm_uri("core"))
        nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_owl_uri("owl#Ontology"))
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#domainGraph"), domainGraph)
        nqw.write_quad(uri, nqw.encode_owl_uri("owl#versionInfo"), versionInfo)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#reasonerClass"), reasonerClass)
        nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
        nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)        

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output a list of the features that are supported (to the cmd line and to the NQ file)
    print("Domain model feature list: ")
    for featureRef in feature_list:
        print(" " + featureRef)
        feature = nqw.encode_ssm_uri(featureRef.replace("feature#", "domain#Feature-"))
        nqw.write_quad(feature, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ModelFeature"))

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Now, output a list of packages in the model, including whether they are enabled
    with open("Packages.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("Label")
        comment_index = header.index("Description")
        if HAS_OPTIONAL_PACKAGES in feature_list:
            enabled_index = header.index("Enabled")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: row = next(reader)

            # Extract the information we need from the subsequent row
            uri = nqw.encode_ssm_uri(row[uri_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])

            # Extract enabled status if present, default to 'true', and report if disabled
            isEnabled = True
            if HAS_OPTIONAL_PACKAGES in feature_list:
                isEnabled = row[enabled_index].lower() == 'true'

            if isEnabled:
                package_list.append(row[uri_index])
                enabled = nqw.encode_boolean("true")
            else:
                print("Package " + row[uri_index] + " is included but not enabled")
                enabled = nqw.encode_boolean("false")

            # Ouput the row
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ModelPackage"))
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            if HAS_OPTIONAL_PACKAGES in feature_list:
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#enabled"), enabled)

    #Echo the same list to the cmd line
    print("Domain model packages enabled: ")
    for packageRef in package_list:
        print(" " + packageRef)

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Scale conversion: used for likelihood, impact, risk and population scales, plus two scales
# not yet used by SSM describing the cost and performance overheads of controls.

def output_scale(nqw, saveHighest, infilename, entity, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    savedValue = -1
    savedUri = ""

    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")
        levelValue_index = header.index("levelValue")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue
            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
            levelValue = nqw.encode_integer(row[levelValue_index])

            # Save the end of scale for later use
            newValue = int(row[levelValue_index])
            if(saveHighest):
                if(savedValue < newValue):
                    savedValue = newValue
                    savedUri = row[uri_index]
            else:
                if(newValue == 0):
                    savedUri = row[uri_index]

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#{}".format(entity)))
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#levelValue"), levelValue)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

    return savedUri
#
# End of each scale, saved for later when converting that scale (actually, only MIN_IMPACT is used).
MAX_TW = ""
MIN_LIKELIHOOD = ""
MIN_IMPACT = ""
MIN_RISK = ""
MIN_POP = ""
MIN_COST = ""
MIN_PERF = ""

#
# Assets and relationships.
#
def output_domain_assets(nqw, unfiltered, heading, entities):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the assets
    with open("DomainAsset.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        isAssertable_index = header.index("isAssertable")
        isVisible_index = header.index("isVisible")
        if(HAS_CONSTRUCTION_STATE in feature_list):
            constructionState_index = header.index("constructionState")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
            isAssertable = nqw.encode_boolean(row[isAssertable_index])
            isVisible = nqw.encode_boolean(row[isVisible_index])
            if(HAS_CONSTRUCTION_STATE in feature_list):
                isConstructionState = nqw.encode_boolean(row[constructionState_index])
            
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_owl_uri("owl#Class"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#isAssertable"), isAssertable)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#isVisible"), isVisible)
            if(HAS_CONSTRUCTION_STATE in feature_list):
                if(row[constructionState_index].lower() == "true" and not unfiltered):
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#isConstructionState"), isConstructionState)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

            # Save the asset for later: key = URI, value = entity reference embedded in other URI
            entities[row[uri_index]] = row[uri_index][len("domain#"):]

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the asset parents
    with open("DomainAssetParents.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        subClassOf_index = header.index("subClassOf")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            subClassOf = nqw.encode_ssm_uri(row[subClassOf_index])

            # Output line we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#subClassOf"), subClassOf)

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_relationships(nqw, unfiltered, heading, entities):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the relationships
    with open("ObjectProperty.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        isAssertable_index = header.index("isAssertable")
        isVisible_index = header.index("isVisible")
        hidden_index = header.index("hidden")
        if(HAS_CONSTRUCTION_STATE in feature_list):
            constructionState_index = header.index("constructionState")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
            hidden = nqw.encode_boolean(row[hidden_index])
            isAssertable = nqw.encode_boolean(row[isAssertable_index])
            isVisible = nqw.encode_boolean(row[isVisible_index])
            if(HAS_CONSTRUCTION_STATE in feature_list):
                isConstructionState = nqw.encode_boolean(row[constructionState_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_owl_uri("owl#ObjectProperty"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#isAssertable"), isAssertable)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#isVisible"), isVisible)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hidden"), hidden)
            if(HAS_CONSTRUCTION_STATE in feature_list):
                if(row[constructionState_index].lower() == "true" and not unfiltered):
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#isConstructionState"), isConstructionState)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

            # Save the relationship for later: key = URI, value = reference embedded in other URI
            entities[row[uri_index]] = row[uri_index][len("domain#"):]

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the relationship type parents
    with open("ObjectPropertyParents.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        subPropertyOf_index = header.index("subPropertyOf")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            subPropertyOf = nqw.encode_ssm_uri(row[subPropertyOf_index])

            # Output line we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#subPropertyOf"), subPropertyOf)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the relationship domains
    with open("ObjectPropertyDomains.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        domain_index = header.index("domain")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            theDomain = nqw.encode_ssm_uri(row[domain_index])

            # Output line we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#domain"), theDomain)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the relationship ranges
    with open("ObjectPropertyRanges.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        range_index = header.index("range")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            theRange = nqw.encode_ssm_uri(row[range_index])

            # Output line we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#range"), theRange)

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Roles, controls, misbehaviours and trustworthiness attributes: all except roles need to be
# expanded into triplets if population models are to be supported.
#
def output_roles(nqw, heading, entities):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the roles
    with open("Role.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
 
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#Role"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

            # Save for later
            entities[row[uri_index]] = row[uri_index][len("domain#Role_"):]

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the asset types that can take each role
    with open("RoleLocations.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        metaLocatedAt_index = header.index("metaLocatedAt")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            metaLocatedAt = nqw.encode_ssm_uri(row[metaLocatedAt_index])

            # Output line we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#metaLocatedAt"), metaLocatedAt)

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_cmr_entity(nqw, unfiltered, entityType, heading, infilename, locfilename, entities):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the properties
    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        isVisible_index = header.index("isVisible")
        if(entityType == "Control"):
            cost_index = header.index("unitCost")
            perf_index = header.index("performanceImpact")

        typ = nqw.encode_ssm_uri("core#" + entityType)

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            (min_uri, av_uri, max_uri) = nqw.encode_ssm_uri(add_minmax(row[uri_index]))
            (min_label, av_label, max_label) = nqw.encode_string(add_minmax(row[label_index]))
            comment = nqw.encode_string(row[comment_index])
            if unfiltered:
                av_isVisible = nqw.encode_boolean("True")
                minmax_isVisible = nqw.encode_boolean("True")
            else:
                av_isVisible = nqw.encode_boolean(row[isVisible_index].lower())
                minmax_isVisible = nqw.encode_boolean("False")
            if(entityType == "Control"):
                unitCost = nqw.encode_ssm_uri(row[cost_index])
                performanceImpact = nqw.encode_ssm_uri(row[perf_index])

            # Output the average version
            nqw.write_quad(av_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#label"), av_label)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isVisible"), av_isVisible)
            if(entityType == "Control"):
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#unitCost"), unitCost)
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#performanceImpact"), performanceImpact)
                

            if(HAS_POPULATION_MODEL in feature_list):
                # Output the min and max versions
                nqw.write_quad(min_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
                nqw.write_quad(min_uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
                nqw.write_quad(min_uri, nqw.encode_rdfs_uri("rdf-schema#label"), min_label)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#isVisible"), minmax_isVisible)
                if(entityType == "Control"):
                    nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#unitCost"), unitCost)
                    nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#performanceImpact"), performanceImpact)

                nqw.write_quad(max_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
                nqw.write_quad(max_uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
                nqw.write_quad(max_uri, nqw.encode_rdfs_uri("rdf-schema#label"), max_label)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#isVisible"), minmax_isVisible)
                if(entityType == "Control"):
                    nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#unitCost"), unitCost)
                    nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#performanceImpact"), performanceImpact)

                # link the three versions
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMin"), min_uri)
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMax"), max_uri)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#minOf"), av_uri)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#maxOf"), av_uri)
            
            # Output a spacer at the end of this resource
            nqw.write_comment("")

            # Save the entity for later: key = URI, value = entity reference embedded in other URI
            entities[row[uri_index]] = row[uri_index][len("domain#"):]

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the asset types that can have each property
    with open(locfilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        metaLocatedAt_index = header.index("metaLocatedAt")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            (min_uri, av_uri, max_uri) = nqw.encode_ssm_uri(add_minmax(row[uri_index]))
            metaLocatedAt = nqw.encode_ssm_uri(row[metaLocatedAt_index])

            # Output line we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), metaLocatedAt)
            if(HAS_POPULATION_MODEL in feature_list):
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), metaLocatedAt)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), metaLocatedAt)

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Trustworthiness attribute erosion, threat causation suppression.
#
def output_twis(nqw, heading, twa_misbehaviour):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the TWIS entries
    with open("TWIS.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        affected_by_index = header.index("affectedBy")
        affects_index = header.index("affects")
    
        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            affected_by = nqw.encode_ssm_uri(row[affected_by_index])
            affects = nqw.encode_ssm_uri(row[affects_index])

            # Save the mapping from TWA to Misbehaviour
            twa = row[affects_index]
            misbehaviour = row[affected_by_index]
            twa_misbehaviour[twa] = misbehaviour

            # Output lines we need to the NQ file
            # Average case
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#TrustworthinessImpactSet"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#affectedBy"), affected_by)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#affects"), affects)

            # Min/max cases : not sure if SSM still needs these but keep them until this can be confirmed 
            # Note that this relies upon the TWIS URI being of the form: domain#TWIS-affects-affected_by
            if(HAS_POPULATION_MODEL in feature_list):
                affected_by = row[affected_by_index][7:]  # remove initial "domain#"
                affects = row[affects_index][7:]

                min_affected_by = affected_by + "_Min"
                max_affected_by = affected_by + "_Max"
                min_affects = affects + "_Min"
                max_affects = affects + "_Max"

                uri = nqw.encode_ssm_uri("domain#TWIS-" + min_affects + "-" + max_affected_by)
                nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#TrustworthinessImpactSet"))
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#affects"), nqw.encode_ssm_uri("domain#" + min_affects))
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#affectedBy"), nqw.encode_ssm_uri("domain#" + max_affected_by))

                uri = nqw.encode_ssm_uri("domain#TWIS-" + max_affects + "-" + min_affected_by)
                nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#TrustworthinessImpactSet"))
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#affects"), nqw.encode_ssm_uri("domain#" + max_affects))
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#affectedBy"), nqw.encode_ssm_uri("domain#" + min_affected_by))

            # Output a spacer at the end of this section
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_mis(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Set the input filename and other parameters
    infilename = "MIS.csv"
        
    # Output the properties
    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        inhibited_index = header.index("inhibited")
        inhibited_by_index = header.index("inhibitedBy")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            inhibited = nqw.encode_ssm_uri(row[inhibited_index])
            inhibited_by = nqw.encode_ssm_uri(row[inhibited_by_index])

            # Output lines we need to the NQ file

            # Average case - we don't need the other two because this is new do the validator can do the expansion
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#MisbehaviourInhibitionSet"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inhibited"), inhibited)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inhibitedBy"), inhibited_by)

        # Output a spacer at the end of this section
        nqw.write_comment("")

#
# Patterns: do not need to be expanded as population triplets.
#
def output_root_patterns(nqw, heading, roles, assets, relationships, nodes, links):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the root pattern
    with open("RootPattern.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")

        # Note that there is a comment field used in the MS Access DB editor, but it is not exported to NQ
        comment_index = header.index("comment")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
 
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#RootPattern"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the root pattern nodes
    with open("RootPatternNodes.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        hasNode_index = header.index("hasNode")
        keyNode_index = header.index("keyNode")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasNode = nqw.encode_ssm_uri(row[hasNode_index])
            keyNode = row[keyNode_index].lower()
 
            # Output lines we need to the NQ file
            if(keyNode == "true"):
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasKeyNode"), hasNode)
            elif(keyNode == "false"):
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasRootNode"), hasNode)
            else:
                raise ValueError("Matching pattern {} has bad keyNode value {}".format(uri,keyNode))

            # Save the node
            if row[hasNode_index] not in nodes:
                nodes[row[hasNode_index]] = create_node(row[hasNode_index], roles, assets)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the root pattern links
    with open("RootPatternLinks.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        hasLink_index = header.index("hasLink")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasLink = nqw.encode_ssm_uri(row[hasLink_index])
 
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasLink"), hasLink)

            # Save the link
            if row[hasLink_index] not in links:
                links[row[hasLink_index]] = create_link(row[hasLink_index], roles, relationships)

    # Output a spacer at the end of this section
    nqw.write_comment("")
    
def output_matching_patterns(nqw, heading, roles, assets, relationships, nodes, links):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the matching pattern
    with open("MatchingPattern.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        hasRootPattern_index = header.index("hasRootPattern")

        # Note that the comment field is not exported to NQ for root patterns, so it may not be necessary here either

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
            hasRootPattern = nqw.encode_ssm_uri(row[hasRootPattern_index])
 
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#MatchingPattern"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasRootPattern"), hasRootPattern)
            
            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the matching pattern nodes
    with open("MatchingPatternNodes.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        has_node_index = header.index("hasNode")
        mandatory_node_index = header.index("mandatoryNode")
        prohibited_node_index = header.index("prohibitedNode")
        sufficient_node_index = header.index("sufficientNode")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            has_node = nqw.encode_ssm_uri(row[has_node_index])
            mandatory_node = row[mandatory_node_index].lower()
            prohibited_node = row[prohibited_node_index].lower()
            sufficient_node = row[sufficient_node_index].lower()

            # Output lines we need to the NQ file
            if mandatory_node == "true":
                if sufficient_node == "true":
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasSufficientNode"), has_node)
                else:
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasNecessaryNode"), has_node)
            elif prohibited_node == "true":
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasProhibitedNode"), has_node)
            else:
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasOptionalNode"), has_node)

            # Save the node
            if row[has_node_index] not in nodes:
                nodes[row[has_node_index]] = create_node(row[has_node_index], roles, assets)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the matching pattern links
    with open("MatchingPatternLinks.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        hasLink_index = header.index("hasLink")
        prohibited_index = header.index("prohibited")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasLink = nqw.encode_ssm_uri(row[hasLink_index])
            prohibited = row[prohibited_index].lower()
 
            # Output lines we need to the NQ file
            if(prohibited == "true"):
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasProhibitedLink"), hasLink)
            else:
                nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasLink"), hasLink)

            # Save the link
            if row[hasLink_index] not in links:
                links[row[hasLink_index]] = create_link(row[hasLink_index], roles, relationships)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the matching pattern relations to DNGs
    with open("MatchingPatternDNG.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        hasDistinctNodeGroup_index = header.index("hasDistinctNodeGroup")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasDistinctNodeGroup = nqw.encode_ssm_uri(row[hasDistinctNodeGroup_index])

            # Output lines we need to the NQ file
            nqw.write_quad(hasDistinctNodeGroup, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#DistinctNodeGroup"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasDistinctNodeGroup"), hasDistinctNodeGroup)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the DNG Nodes
    with open("DistinctNodeGroupNodes.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        hasNode_index = header.index("hasNode")
 
        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasNode = nqw.encode_ssm_uri(row[hasNode_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasNode"), hasNode)
 
    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_construction_patterns(nqw, heading, roles, assets, relationships, nodes, links, cppredecessor, cpsequence):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Determine the source of construction sequence priorities
    if(HAS_CONSTRUCTION_DEPENDENCIES in feature_list):
        # Extract predecessor/successor relationships and create the CP partial sequence 
        create_construction_sequence(cppredecessor, cpsequence)

    # Output the construction pattern
    with open("ConstructionPattern.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        hasMatchingPattern_index = header.index("hasMatchingPattern")
        if(HAS_CONSTRUCTION_DEPENDENCIES not in feature_list):
            hasPriority_index = header.index("hasPriority")
            use_marker = False
            marker = False
        else:
            use_marker = "marker" in header
            if use_marker:
                marker_index = header.index("marker")
            else:
                marker = False
        iterate_index = header.index("iterate")
        maxIterations_index = header.index("maxIterations")

        try:
            for row in reader:
                # Skip the first line which contains default values for csvformat
                if DUMMY_URI in row: continue

                # Skip this line if it is in a package that is not enabled
                if not row[package_index] in package_list: continue

                # Extract the information we need from the next row
                uri = nqw.encode_ssm_uri(row[uri_index])
                package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
                label = nqw.encode_string(row[label_index])
                comment = nqw.encode_string(row[comment_index])
                hasMatchingPattern = nqw.encode_ssm_uri(row[hasMatchingPattern_index])
                marker = "false"
                if(HAS_CONSTRUCTION_DEPENDENCIES in feature_list):
                    # set the priority to the computed rank in the partial sequence
                    hasPriority = nqw.encode_integer(cpsequence[row[uri_index]])

                    # and set the marker flag if this pattern is a marker pattern
                    if use_marker:
                        marker = (row[marker_index].lower == "true")
                else:
                    # set the priority to the hasPriority value from the CSV file
                    hasPriority = nqw.encode_integer(row[hasPriority_index])
                iterate = nqw.encode_boolean(row[iterate_index].lower())
                maxIterations = nqw.encode_integer(row[maxIterations_index])
    
                # Output lines we need to the NQ file, but skipping the pattern if it is a marker pattern
                if not marker:
                    nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ConstructionPattern"))
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#inPackage"), package)
                    nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
                    nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasMatchingPattern"), hasMatchingPattern)
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasPriority"), hasPriority)
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#iterate"), iterate)
                    nqw.write_quad(uri, nqw.encode_ssm_uri("core#maxIterations"), maxIterations)

                    # Output a spacer at the end of this resource
                    nqw.write_comment("")

        except StopIteration:
            pass

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the inferred nodes
    with open("InferredNodeSetting.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        inPattern_index = header.index("inPattern")
        hasNode_index = header.index("hasNode")
        hasSetting_index = header.index("hasSetting")
        displayedAtNode_index = header.index("displayedAtNode")
        displayedAtLink_index = header.index("displayedAtLink")
        displayedAt_index = header.index("displayedAt")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            inPattern = nqw.encode_ssm_uri(row[inPattern_index])
            hasNode = nqw.encode_ssm_uri(row[hasNode_index])
            hasSetting = nqw.encode_ssm_uri(row[hasSetting_index])
            displayedAtNode = row[displayedAtNode_index].lower()
            displayedAtLink = row[displayedAtLink_index].lower()
            displayedAt = nqw.encode_ssm_uri(row[displayedAt_index])

            # Output lines we need to the NQ file
            nqw.write_quad(inPattern, nqw.encode_ssm_uri("core#hasInferredNode"), hasNode)
            nqw.write_quad(inPattern, nqw.encode_ssm_uri("core#hasInferredNodeSetting"), hasSetting)
            nqw.write_quad(hasSetting, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#InferredNodeSetting"))
            nqw.write_quad(hasSetting, nqw.encode_ssm_uri("core#hasNode"), hasNode)
            if(displayedAtNode == "true"):
                nqw.write_quad(hasSetting, nqw.encode_ssm_uri("core#displayedAtNode"), displayedAt)
            else:
                nqw.write_quad(hasSetting, nqw.encode_ssm_uri("core#displayedAtLink"), displayedAt)

            # Save the node
            if row[hasNode_index] not in nodes:
                nodes[row[hasNode_index]] = create_node(row[hasNode_index], roles, assets)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the inferred node setting includes
    with open("InferredNodeSettingIncludes.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        includesNodeInURI_index = header.index("includesNodeInURI")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            includesNodeInURI = nqw.encode_ssm_uri(row[includesNodeInURI_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#includesNodeInURI"), includesNodeInURI)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the inferred links
    with open("ConstructionPatternLinks.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        hasInferredLink_index = header.index("hasInferredLink")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            hasInferredLink = nqw.encode_ssm_uri(row[hasInferredLink_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasInferredLink"), hasInferredLink)

            # Save the link
            if row[hasInferredLink_index] not in links:
                links[row[hasInferredLink_index]] = create_link(row[hasInferredLink_index], roles, relationships)

def create_construction_sequence(cppredecessor, cpsequence):

    with open("ConstructionPattern.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Initialise the predecessors dictionary entry (an empty list) and sequence number (initially zero)
            cppredecessor[row[uri_index]] = []
            cpsequence[row[uri_index]] = 0

    # Get the construction pattern predecessors and save them
    with open("ConstructionPredecessor.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        predecessor_index = header.index("hasPredecessor")
        fake_index = header.index("fake")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract and save the information we need
            uri = row[uri_index]
            predecessor = row[predecessor_index]
            fake = row[fake_index].lower()

            # Add the predecessor to the set of predecessors for this pattern
            if not fake == "true" and predecessor not in cppredecessor[uri]:
                cppredecessor[uri].append(predecessor)

    # Get the construction pattern successors and save them
    with open("ConstructionSuccessor.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        successor_index = header.index("hasSuccessor")
        fake_index = header.index("fake")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract and save the information we need
            uri = row[uri_index]
            successor = row[successor_index]
            fake = row[fake_index].lower()

            # Add the URI to the set of predecessors of the successor
            if not fake == "true" and uri not in cppredecessor[successor]:
                cppredecessor[successor].append(uri)

    # Use the data to find patterns and assign their priority
    finished = False
    i = 1
    while not finished:
        # Set finished flag until we find something still to do
        finished = True
        
        # Find CP with no remaining predecessors, and set their sequence number to a positive value 
        for uri in cpsequence:
            if uri in cppredecessor:
                if (cpsequence[uri] == 0) and (len(cppredecessor[uri])==0):
                    # Found something so the outer loop must continue
                    finished = False
                    
                    # Mark this CP for removal
                    cpsequence[uri] = -1
            else:
                print("Error: CP {} has no list of predecessors".format(uri.replace("domain#CP-","")))

        for uri in cpsequence:
            if cpsequence[uri] < 0:
                # Remove this CP from the list of predecessors of other CP
                for cp in cppredecessor:
                    if uri in cppredecessor[cp]:
                        cppredecessor[cp].remove(uri)

                # Set the rank of the removed CP
                cpsequence[uri] = i

        i = i + 1

#
# Control strategies, threats and threat categories and compliance sets: no triplets needed,
# but threats and CSGs do have some min/max properties.
#
def output_threat_categories(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the threat categories
    with open("ThreatCategory.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        label_index = header.index("label")
        comment_index = header.index("comment")

        # Note that threat categories are not in packages - they are treated like part of package#Core
        
        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue
            
            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ThreatCategory"))
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_compliance_sets(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the compliance sets
    with open("ComplianceSet.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")

        try:
            for row in reader:
                # Skip the first line which contains default values for csvformat
                if DUMMY_URI in row: continue

                # Skip this line if it is in a package that is not enabled
                if not row[package_index] in package_list: continue

                # Extract the information we need from the next row
                uri = nqw.encode_ssm_uri(row[uri_index])
                label = nqw.encode_string(row[label_index])
                comment = nqw.encode_string(row[comment_index])
    
                # Output lines we need to the NQ file
                nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ComplianceSet"))
                nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
                nqw.write_quad(uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)

                # Output a spacer at the end of this resource
                nqw.write_comment("")
        except StopIteration:
            pass

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the required compliance threats
    with open("ComplianceSetThreats.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        requiresTreatmentOf_index = header.index("requiresTreatmentOf")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            requiresTreatmentOf = nqw.encode_ssm_uri(row[requiresTreatmentOf_index])
 
            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#requiresTreatmentOf"), requiresTreatmentOf)

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_threats(nqw, heading, misbehaviours, twas, roles, misbehaviour_sets, twa_sets):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the threats
    with open("Threat.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        has_category_index = header.index("hasCategory")
        applies_to_index = header.index("appliesTo")
        threatens_index = header.index("threatens")
        has_frequency_index = header.index("hasFrequency")
        currentRisk_index = header.index("currentRisk")
        futureRisk_index = header.index("futureRisk")
        if(HAS_THREAT_TYPE_FLAGS in feature_list):
            secondaryThreat_index = header.index("secondaryThreat")
            normalOperation_index = header.index("normalOperation")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row

            # Get expansion prefix, which assumes the base URI is of the form domain#Target.Effect.Pattern.[Tail] where Tail can include further dots
            bits = row[uri_index][7:].split(".")
            if len(bits) < 4:
                raise ValueError("Threat URI has invalid form (needs at least 3 fullstops): " + row[uri_index])
            prefix = bits[0] + "." + bits[1]
            tail = bits[3]

            # Create the expanded triplet of URIs using this prefix
            (min_uri, av_uri, max_uri) = nqw.encode_ssm_uri(add_minmax(row[uri_index], prefix))

            # Get the other data
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            label = nqw.encode_string(row[label_index])
            comment = nqw.encode_string(row[comment_index])
            has_category = nqw.encode_ssm_uri(row[has_category_index])
            applies_to = nqw.encode_ssm_uri(row[applies_to_index])
            threatens = nqw.encode_ssm_uri(row[threatens_index])
            has_frequency = nqw.encode_ssm_uri(row[has_frequency_index])
            if(HAS_RISK_TYPE_FLAGS in feature_list):
                currentRisk = nqw.encode_boolean(row[currentRisk_index].lower())
                futureRisk = nqw.encode_boolean(row[futureRisk_index].lower())
            if(HAS_THREAT_TYPE_FLAGS in feature_list):
                secondaryThreat = nqw.encode_boolean(row[secondaryThreat_index].lower())
                normalOperation = nqw.encode_boolean(row[normalOperation_index].lower())
            
            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#Threat"))
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasCategory"), has_category)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#appliesTo"), applies_to)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#threatens"), threatens)

            # If it is not a compliance threat, add extra lines we will need
            if(has_frequency):
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasFrequency"), has_frequency)
                if(HAS_RISK_TYPE_FLAGS in feature_list):
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isCurrentRisk"), currentRisk)
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isFutureRisk"), futureRisk)
                if(HAS_THREAT_TYPE_FLAGS in feature_list):
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isSecondaryThreat"), secondaryThreat)
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isNormalOp"), normalOperation)
                if(HAS_POPULATION_MODEL in feature_list):
                    # Link the min/max and average URIs
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMin"), min_uri)
                    nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMax"), max_uri)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the primary threat causes (entry points)
    with open("ThreatEntryPoints.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        hasEntryPoint_index = header.index("hasEntryPoint")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_has_entry_point = nqw.encode_ssm_uri(row[hasEntryPoint_index])

            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasEntryPoint"), av_has_entry_point)

            # Save the trustworthiness attribute set for later
            twas_uri = row[hasEntryPoint_index]
            if(twas_uri not in twa_sets):
                twa_sets[twas_uri] = create_set(twas_uri, "Trustworthiness Attribute", twas, roles)

            # Construct and save the associated misbehaviour set for later
            twa = twa_sets[twas_uri]["hasTrustworthinessAttribute"]
            twas_prefix = twa.replace("domain#", "domain#TWAS-")
            misbehaviour = twa_misbehaviour[twa]
            ms_prefix = misbehaviour.replace("domain#", "domain#MS-")             
            ms_uri = twas_uri.replace(twas_prefix, ms_prefix)
            if(ms_uri not in misbehaviour_sets):
                misbehaviour_sets[ms_uri] = create_set(ms_uri, "Misbehaviour", misbehaviours, roles)

    # Output a spacer at the end of this section
    nqw.write_comment("")
    
    # Output the secondary threat causes (secondary effect conditions)
    with open("ThreatSEC.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        has_sec_index = header.index("hasSecondaryEffectCondition")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_has_sec = nqw.encode_ssm_uri(row[has_sec_index])  # a MisbehaviourSet

            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasSecondaryEffectCondition"), av_has_sec)

            # Save the misbehaviour set for later
            if(row[has_sec_index] not in twa_sets):
                misbehaviour_sets[row[has_sec_index]] = create_set(row[has_sec_index], "Misbehaviour", misbehaviours, roles)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the threat effects (caused misbehaviours)
    with open("ThreatEffects.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        causes_misbehaviour_index = header.index("causesMisbehaviour")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_causes_misbehaviour = nqw.encode_ssm_uri(row[causes_misbehaviour_index])

            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#causesMisbehaviour"), av_causes_misbehaviour)

            # Save the misbehaviour set for later
            if(row[causes_misbehaviour_index] not in twa_sets):
                misbehaviour_sets[row[causes_misbehaviour_index]] = create_set(row[causes_misbehaviour_index], "Misbehaviour", misbehaviours, roles)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the CSG blocks threat relationships
    with open("ControlStrategyBlocks.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        blocks_index = header.index("blocks")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_blocks = nqw.encode_ssm_uri(row[blocks_index])
            
            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#blocks"), av_blocks)

    # Output a spacer at the end of this section
    nqw.write_comment("")

    # Output the CSG mitigates threat relationships
    with open("ControlStrategyMitigates.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        mitigates_index = header.index("mitigates")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_mitigates = nqw.encode_ssm_uri(row[mitigates_index])
            
            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#mitigates"), av_mitigates)

    # Output a spacer at the end of this section
    nqw.write_comment("")
    
    # Output the CSG triggers threat relationships
    with open("ControlStrategyTriggers.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        triggers_index = header.index("triggers")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_triggers = nqw.encode_ssm_uri(row[triggers_index])
            
            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#triggers"), av_triggers)

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_control_strategies(nqw, heading, controls, roles, control_sets):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Output the control strategies
    with open("ControlStrategy.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        label_index = header.index("label")
        comment_index = header.index("comment")
        has_blocking_effect_index = header.index("hasBlockingEffect")
        if(HAS_RISK_TYPE_FLAGS in feature_list):
            currentRisk_index = header.index("currentRisk")
            futureRisk_index = header.index("futureRisk")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Get expansion prefix, which assumes the base URI is of the form domain#CSG-Body or domain#CSG-Body-[Tail] where Tail can include further dashes
            bits = row[uri_index][7:].split("-")
            if len(bits) < 2:
                raise ValueError("CSG URI has invalid form (needs at least one hyphen): " + row[uri_index])
            prefix = bits[0] + "-" + bits[1]

            # Create the expanded triplet of URIs using this prefix
            (min_uri, av_uri, max_uri) = nqw.encode_ssm_uri(add_minmax(row[uri_index], prefix))

            # Get the other data
            package = nqw.encode_ssm_uri(row[package_index].replace("package#", "domain#Package-"))
            comment = nqw.encode_string(row[comment_index])
            label = nqw.encode_string(row[label_index])
            has_blocking_effect = nqw.encode_ssm_uri(row[has_blocking_effect_index])
            if(HAS_RISK_TYPE_FLAGS in feature_list):
                currentRisk = nqw.encode_boolean(row[currentRisk_index].lower())
                futureRisk = nqw.encode_boolean(row[futureRisk_index].lower())

            # Output lines we need to the NQ file
            nqw.write_quad(av_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#ControlStrategy"))
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#inPackage"), package)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#comment"), comment)
            nqw.write_quad(av_uri, nqw.encode_rdfs_uri("rdf-schema#label"), label)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasBlockingEffect"), has_blocking_effect)
            if(HAS_RISK_TYPE_FLAGS in feature_list):
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isCurrentRisk"), currentRisk)
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isFutureRisk"), futureRisk)
            if(HAS_POPULATION_MODEL in feature_list):
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMin"), min_uri)
                nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasMax"), max_uri)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")


    # Output the CSG control sets
    with open("ControlStrategyControls.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        has_control_set_index = header.index("hasControlSet")
        optional_index = header.index("optional")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            av_uri = nqw.encode_ssm_uri(row[uri_index])
            av_has_control_set = nqw.encode_ssm_uri(row[has_control_set_index])
            optional = row[optional_index].lower()
            if optional == "true":
                # Optional CS
                relation = nqw.encode_ssm_uri("core#hasOptionalCS")
            else:
                # Mandatory CS here
                relation = nqw.encode_ssm_uri("core#hasMandatoryCS")

            # Write out the line we need
            nqw.write_quad(av_uri, relation, av_has_control_set)

            # Save the control set for later
            if(row[has_control_set_index] not in twa_sets):
                control_sets[row[has_control_set_index]] = create_set(row[has_control_set_index], "Control", controls, roles)

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Default settings: CASettings does need to be expanded if population triplets are used,
# as the SSM GUI needs an isAssertable property to exist for every control (including min 
# and max coverage variants).
#
def output_casettings(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Set the input filename and other parameters based on the argument 'entityType'
    infilename = "CASetting.csv"
    settingType = "CASetting"

    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)
        
        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        metaLocatedAt_index = header.index("metaLocatedAt")
        has_control_index = header.index("hasControl")
        is_assertable_index = header.index("isAssertable")
        has_level_index = header.index("hasLevel")
        independent_levels_index = header.index("independentLevels")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            control = row[has_control_index][7:]  # remove initial "domain#"
            (min_uri, av_uri, max_uri) = nqw.encode_ssm_uri(add_minmax(row[uri_index], control))
            (min_control, av_control, max_control) = nqw.encode_ssm_uri(add_minmax(row[has_control_index]))
            asset = nqw.encode_ssm_uri(row[metaLocatedAt_index])
            is_assertable = nqw.encode_boolean(row[is_assertable_index].lower())
            has_level = nqw.encode_ssm_uri(row[has_level_index])
            if(HAS_POPULATION_MODEL in feature_list):
                # Use the value in the table to specify how levels are distributed over a population
                independent_levels = nqw.encode_boolean(row[independent_levels_index].lower())
            else:
                # Insert the value 'false' if asset populations are not supported
                independent_levels = nqw.encode_boolean("false")

            # Output the average coverage control default settings
            nqw.write_quad(av_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#{}".format(settingType)))
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasControl"), av_control)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), asset)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#isAssertable"), is_assertable)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#hasLevel"), has_level)
            nqw.write_quad(av_uri, nqw.encode_ssm_uri("core#independentLevels"), independent_levels)

            # SSM can generate triplets, but the GUI still needs the isAssertable property, so these must be expanded
            if(HAS_POPULATION_MODEL in feature_list):
                # Output the minimum coverage control default settings
                nqw.write_quad(min_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#{}".format(settingType)))
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#hasControl"), min_control)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), asset)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#isAssertable"), is_assertable)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#hasLevel"), has_level)
                nqw.write_quad(min_uri, nqw.encode_ssm_uri("core#independentLevels"), independent_levels)

                # Output the maximum coverage control default settings
                nqw.write_quad(max_uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#{}".format(settingType)))
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#hasControl"), max_control)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#metaLocatedAt"), asset)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#isAssertable"), is_assertable)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#hasLevel"), has_level)
                nqw.write_quad(max_uri, nqw.encode_ssm_uri("core#independentLevels"), independent_levels)

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_twaa_default_levels(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    infilename = "TWAADefaultSetting.csv"

    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)
        
        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        uri_index = header.index("URI")
        package_index = header.index("package")
        metaLocatedAt_index = header.index("metaLocatedAt")
        twa_index = header.index("hasTrustworthinessAttribute")
        has_level_index = header.index("hasLevel")
        independent_levels_index = header.index("independentLevels")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            asset = nqw.encode_ssm_uri(row[metaLocatedAt_index])
            twa = nqw.encode_ssm_uri(row[twa_index])
            has_level = nqw.encode_ssm_uri(row[has_level_index])
            if(HAS_POPULATION_MODEL in feature_list):
                # Use the value in the table to specify how levels are distributed over a population
                independent_levels = nqw.encode_boolean(row[independent_levels_index].lower())
            else:
                # Insert the value 'false' if asset populations are not supported
                independent_levels = nqw.encode_boolean("false")

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#TWAADefaultSetting"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#metaLocatedAt"), asset)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasTrustworthinessAttribute"), twa)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasLevel"), has_level)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#independentLevels"), independent_levels)

            # We don't need triplet expansion now that SSM generates triplets from the average tw attribute

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_ma_default_levels(nqw, heading):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # Set the input filename and other parameters based on the argument 'entityType'
    infilename = "MADefaultSetting.csv"

    with open(infilename, newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)
        
        # Check that the table is as expected: if fields are missing this will raise an exception
        header = next(reader)
        package_index = header.index("package")
        uri_index = header.index("URI")
        metaLocatedAt_index = header.index("metaLocatedAt")
        has_misbehaviour_index = header.index("hasMisbehaviour")
        has_level_index = header.index("hasLevel")

        for row in reader:
            # Skip the first line which contains default values for csvformat
            if DUMMY_URI in row: continue

            # Skip this line if it is in a package that is not enabled
            if not row[package_index] in package_list: continue

            # Extract the information we need from the next row
            uri = nqw.encode_ssm_uri(row[uri_index])
            asset = nqw.encode_ssm_uri(row[metaLocatedAt_index])
            misbehaviour = nqw.encode_ssm_uri(row[has_misbehaviour_index])
            has_level = nqw.encode_ssm_uri(row[has_level_index])

            # Output lines we need to the NQ file
            nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), nqw.encode_ssm_uri("core#MADefaultSetting"))
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#metaLocatedAt"), asset)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasMisbehaviour"), misbehaviour)
            nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasLevel"), has_level)

            # We don't need triplet expansion now that SSM generates triplets from the average misbehaviour

            # Output a spacer at the end of this resource
            nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Derived quantities: none of these need to be expanded as population triplets.
#
def output_nodes(nqw, heading, nodes):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    typ = nqw.encode_ssm_uri("core#Node")

    # Output the nodes
    for key in nodes:
        # Get the node
        node = nodes[key]

        # Get the data
        uri = nqw.encode_ssm_uri(key)
        metaHasAsset = nqw.encode_ssm_uri(node["metaHasAsset"])
        hasRole = nqw.encode_ssm_uri(node["hasRole"])

        # Output lines we need to the NQ file
        nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#metaHasAsset"), metaHasAsset)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#hasRole"), hasRole)

        # Output a spacer at the end of this resource
        nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_role_links(nqw, heading, links):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    typ = nqw.encode_ssm_uri("core#RoleLink")

    for key in links:
        # Get the link
        link = links[key]

        # Get the data
        uri = nqw.encode_ssm_uri(key)
        linksFrom = nqw.encode_ssm_uri(link["linksFrom"])
        linkType = nqw.encode_ssm_uri(link["linkType"])
        linksTo = nqw.encode_ssm_uri(link["linksTo"])

        # Write the lines we need
        nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#linkType"), linkType)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#linksFrom"), linksFrom)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#linksTo"), linksTo)

        # Output a spacer at the end of this resource
        nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

def output_sets(nqw, entityType, heading, entity_sets):
    # Output a heading for this section
    nqw.write_comment("")
    nqw.write_comment(heading)
    nqw.write_comment("")

    # get a uri without the prefix
    if(entityType == "Control"):
        typ = nqw.encode_ssm_uri("core#ControlSet")
        propertyKey = "hasControl"
    elif(entityType == "Misbehaviour"):
        typ = nqw.encode_ssm_uri("core#MisbehaviourSet")
        propertyKey = "hasMisbehaviour"
    elif(entityType == "TrustworthinessAttribute"):
        typ = nqw.encode_ssm_uri("core#TrustworthinessAttributeSet")
        propertyKey = "hasTrustworthinessAttribute"
    else:
        # Error - unknown type
        raise ValueError("Unknown entity type '" + entityType + "'")

    for key in entity_sets:
        # Get the link
        entity_set = entity_sets[key]

        # Get the data
        uri = nqw.encode_ssm_uri(key)
        locatedAt = nqw.encode_ssm_uri(entity_set["locatedAt"])
        hasEntity = nqw.encode_ssm_uri(entity_set[propertyKey])

        # Write the lines we need
        nqw.write_quad(uri, nqw.encode_rdfns_uri("22-rdf-syntax-ns#type"), typ)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#" + propertyKey), hasEntity)
        nqw.write_quad(uri, nqw.encode_ssm_uri("core#locatedAt"), locatedAt)

        # Output a spacer at the end of this resource
        nqw.write_comment("")

    # Output a spacer at the end of this section
    nqw.write_comment("")

#
# Helper functions.
#
def add_minmax(base, prefix=None):
    if base == "": return ""
    if prefix == None:
        mins = base + MIN_SUFFIX
        maxs = base + MAX_SUFFIX
    else:
        if prefix not in base:
            raise ValueError("'" + prefix + "' cannot be found in '" + base + "'")
        pre, prefix, post = base.partition(prefix)
        mins = pre + prefix + MIN_SUFFIX + post
        maxs = pre + prefix + MAX_SUFFIX + post
        if prefix in post:
            # This can legitimately happen and it's almost certainly okay to just go with the prefix's first occurrence
            # We print a warning though in case it has gone wrong
            print("WARNING: multiple '" + prefix + "' found in '" + base + "'. 'Min' output is '" + mins + "'")
    return mins, base, maxs

def create_node(uri, roles, assets):
    # create a dictionary to hold the link properties
    node = {}

    # get a uri without the prefix
    short_uri = uri[len("domain#Node-"):]

    # find the role
    found = False
    for role in roles:
        if(short_uri.startswith(roles[role] + "-")):
            # Extract the role into the link entity
            node["hasRole"] = role
            short_uri = short_uri[len(roles[role]) + 1:]
            found = True
            break
    if not found:
        # Error - couldn't find the from role
        raise ValueError("Bad Node URI " + uri + " does not have a valid role")

    # what remains should be the asset type, so just check it is a valid asset
    asset = "domain#" + short_uri
    if(asset not in assets):
        # Error - couldn't find the asset type
        raise ValueError("Bad Node URI " + uri + " does not have a valid asset type")

    node["metaHasAsset"] = asset

    return node

def create_link(uri, roles, relationships):
    # create a dictionary to hold the link properties
    link = {}

    # get a uri without the prefix
    short_uri = uri[len("domain#Link-"):]

    # find the first role (the from role)
    found = False
    for role in roles:
        if(short_uri.startswith(roles[role]+ "-")):
            # Extract the role into the link entity
            link["linksFrom"] = role
            short_uri = short_uri[len(roles[role]) + 1:]
            found = True
            break    
    if not found:
        # Error - couldn't find the from role
        raise ValueError("Bad Role Link URI " + uri + " is not from a valid role")

    # find the link type
    found = False
    for relationship in relationships:
        if(short_uri.startswith(relationships[relationship]+ "-")):
            # Extract the role into the link entity
            link["linkType"] = relationship
            short_uri = short_uri[len(relationships[relationship]) + 1:]
            found = True
            break
    if not found:
        # Error - couldn't find the relationship type
        raise ValueError("Bad Role Link URI " + uri + " does not have a valid relationship type")

    # what remains should be the linksTo role, so just check it is a valid role
    role = "domain#Role_" + short_uri
    if(role not in roles):
        # Error - couldn't find the to role
        raise ValueError("Bad Role Link URI " + uri + " is not to a valid role")

    link["linksTo"] = role

    return link

def create_set(uri, entityType, entities, roles):
    # create a dictionary to hold the set properties
    entity_set = {}

    # get a uri without the prefix
    if(uri.startswith("domain#CS-")):
        short_uri = uri[len("domain#CS-"):]
        prop = "hasControl"
    elif(uri.startswith("domain#MS-")):
        short_uri = uri[len("domain#MS-"):]
        prop = "hasMisbehaviour"
    elif(uri.startswith("domain#TWAS-")):
        short_uri = uri[len("domain#TWAS-"):]
        prop = "hasTrustworthinessAttribute"
    else:
        # Error - URI doesn't match the entity type
        raise ValueError("Bad " + entityType + " Set URI " + uri + " does not comply with the schema")

    # find the entity in the entity_list (keys = entity URIs)
    found = False
    for entity in entities:
        if(short_uri.startswith(entities[entity]+ "-")):
            # Insert properties based on this entity
            entity_set[prop] = entity
            short_uri = short_uri[len(entities[entity]) + 1:]
            found = True
            break
    if not found:
        # Error - couldn't find the specific entity
        raise ValueError("Bad " + entityType + " Set URI " + uri + " does not relate to a valid " + entityType.toString)

    # what remains should be the location, so just check it is a valid role
    role = "domain#Role_" + short_uri
    if(role not in roles):
        # Error - URI doesn't match the entity type
        raise ValueError("Bad " + entityType + " Set URI " + uri + " does not relate to a valid role")
    
    entity_set["locatedAt"] = role

    return entity_set

def output_mapping_file(mapping_filename, ontology, domain_graph):
    with open("DomainAsset.csv", newline="") as csvfile:
        # Create the CSV reader object
        reader = csv.reader(csvfile)

        header = next(reader)
        uri_index = header.index("URI")
        icon_index = header.index("icon")

        # Skip the first line of data as there is a "comment" column
        next(reader)

        doc = {
            "ontology": ontology,
            "graph": domain_graph,
            "defaultUserAccess": True,
            "icons": {}
        }

        for row in reader:
            icon = row[icon_index]
            if icon:
                uri = nqwriter.SSM_PREFIX + "/" + row[uri_index]
                doc["icons"][uri] = icon
    with open(mapping_filename, "w") as output:
        output.write(json.dumps(doc, indent=4))

def log_sequence(log, header, cppredecessor, cpsequence):
    od = collections.OrderedDict(sorted(cpsequence.items()))
    log.write("{}\n".format(header))
    for key in od.keys():
        log.write("{}: {}".format(key.replace("domain#CP-",""), cpsequence[key]))
        if key in cppredecessor:
            values = cppredecessor[key]
            i = len(values)
            if i > 0:
                log.write(", predecessors: ")
                for uri in values:
                    i = i - 1
                    if(i==0):
                        log.write("{}\n".format(uri.replace("domain#CP-","")))
                    else:
                        log.write("{}, ".format(uri.replace("domain#CP-","")))
            else:
                log.write(", no predecessors\n")
        else:
            log.write(": found no predecessors list\n")
    log.write("\n")

####################################################################################################################################################
#
# MAIN PROGRAM
#

# Marshall command line arguments
parser = argparse.ArgumentParser(description="Convert from CSV files to NQ")
parser.add_argument("-l", "--log", dest="log", metavar="filename", help="Logfile for diagnostic output")
parser.add_argument("-i", "--input", dest="input", required=True, metavar="directory", help="Directory containing CSV files for input")
parser.add_argument("-o", "--output", dest="output", required=True, metavar="filename", help="Output NQ filename")
parser.add_argument("-m", "--mapping", dest="mapping", metavar="filename", help="Output JSON icon-mapping filename")
parser.add_argument("-u", "--unfiltered", help="Causes SSM GUI Misbehaviour and TWA visibility flags to be set to true, construction state flags to false.", action="store_true")
parser.add_argument("-e", "--expanded", help="Add population model support by expanding relevant structures", action="store_true")
parser.add_argument("-v", "--version", help="Set the versionInfo string (defaults to timestamp) '-unfiltered' will be added to the version string if '-u' is used.")
parser.add_argument("-n", "--name", help="Set the domainGraph string (defaults to what is found in DomainModel.csv). '-unexpanded' will be appended for population models unless '-e' is used.")
parser.add_argument("-b", "--label", help="Set the rdfs:label property (defaults to what is found in DomainModel.csv).")
raw = parser.parse_args()
args = vars(raw)

if(raw.unfiltered):
    print("Misbehaviour and TWA visibility flags set to TRUE, construction state flags to false")
else:
    print("Misbehaviour and TWA visibility flags use domain model specifications")

if(raw.expanded):
    print("Expanding population triplets")
else:
    print("Not expanding population triplets")

# If the user has not specified a version string to use, then use the ISO timestamp
if (not args["version"]):
    args["version"] = datetime.datetime.now().replace(microsecond=0).isoformat()

# Extract output filenames
nq_filename = os.path.join(os.getcwd(), args["output"])
if args["mapping"]:
    output_mapping = True
    mapping_filename = os.path.join(os.getcwd(), args["mapping"])
else:
    output_mapping = False

# Open the log file stream
if args["log"]:
    log_mapping = True
    log_filename = os.path.join(os.getcwd(), args["log"])
    log = open(log_filename, mode="w")
else:
    log_mapping = False

# Extract and enter input folder
csv_directory = args["input"]
os.chdir(csv_directory)

# Need to keep track of features in this domain model
feature_list = []       # start with an empty list of features supported by the domain model structure
package_list = []       # start with an empty list of submodels included as enabled domain model packages

# We also need to keep track of some foundational entities
assets = {}             # will be filled with Asset URI
relationships = {}      # will be filled with Relationship URI
controls = {}           # will be filled with Control URI
misbehaviours = {}      # will be filled with Misbehaviour URI
twas = {}               # will be filled with Trustworthiness Attribute URI
roles = {}              # will be filled with Role URI

cppredecessor = {}                      # will be filled with lists of predecessor CPs
cpsequence = collections.OrderedDict()  # will be filled with the calculated priority of each CP

twa_misbehaviour = {}   # will be filled with the Misbehaviour per TWA, gleaned from the TWIS

control_sets = {}       # will be filled with Control Set URI, gleaned from CSG controls
misbehaviour_sets = {}  # will be filled with Misbehaviour Set URI, gleaned from Threat effects and SECs
twa_sets = {}           # will be filled with Trustworthiness Attribute Set URI, gleaned from Threat entry points
nodes = {}              # will be filled with Node URI, gleaned from root, matching and construction patterns
role_links = {}         # will be filled with RoleLink URI, gleaned from root, matching and construction patterns

# Open the output nq stream
with open(nq_filename, mode="w") as output:
    # Create the NQ formatter object
    nqw = nqwriter.NQWriter(output)
    
    # Process the first CSV file: the domain model definitions which include the graph URI stored in the NQ writer
    output_domain_model(nqw, raw.unfiltered, "Domain model namespace, graph and reasoning class")
    
    # Output scales
    MAX_TW = output_scale(nqw, True, "TrustworthinessLevel.csv", "TrustworthinessLevel", "Scale for (asset) Trustworthiness Levels")
    MIN_LIKELIHOOD = output_scale(nqw, False, "Likelihood.csv", "Likelihood", "Scale for (threat or asset behaviour) Likelihood Levels")
    MIN_IMPACT = output_scale(nqw, False, "ImpactLevel.csv", "ImpactLevel", "Scale for (asset behaviour) Impact Levels")
    MIN_RISK = output_scale(nqw, False, "RiskLevel.csv", "RiskLevel", "Scale for (threat or asset behaviour) Risk Levels")
    MIN_POP = output_scale(nqw, False, "PopulationLevel.csv", "PopulationLevel", "Scale for asset Population Levels")
    
    # Two scales that are not yet used by SSM
    MIN_COST = output_scale(nqw, False, "CostLevel.csv", "CostLevel", "Scale for Control Cost Levels")
    MIN_PERF = output_scale(nqw, False, "PerformanceImpactLevel.csv", "PerformanceImpactLevel", "Scale for Control Performance Overhead Levels")
    
    # Output assets and relationships, saving them for later
    output_domain_assets(nqw, raw.unfiltered, "Domain asset definitions", assets)
    output_relationships(nqw, raw.unfiltered, "Asset relationship definitions", relationships)

    # Output Roles, Controls, Misbehaviours and TWA, saving them for later
    output_roles(nqw, "Role definitions", roles)
    output_cmr_entity(nqw, raw.unfiltered, "Control", "Control definitions", "Control.csv", "ControlLocations.csv", controls)
    output_cmr_entity(nqw, raw.unfiltered, "Misbehaviour", "Misbehaviour definitions", "Misbehaviour.csv", "MisbehaviourLocations.csv", misbehaviours)
    output_cmr_entity(nqw, raw.unfiltered, "TrustworthinessAttribute", "Trustworthiness Attribute definitions", "TrustworthinessAttribute.csv", "TWALocations.csv", twas)

    # Output TWIS and MIS structures
    output_twis(nqw, "Trustworthiness Impact Set definitions (relationship between Misbehaviours and TWAs)", twa_misbehaviour)
    output_mis(nqw, "Misbehaviour Inhibition Sets (relationship between Misbehaviours and Controls)")

    # Output Patterns, saving nodes and links for later
    output_root_patterns(nqw, "Root pattern definitions", roles, assets, relationships, nodes, role_links)
    output_matching_patterns(nqw, "Matching pattern definitions", roles, assets, relationships, nodes, role_links)
    output_construction_patterns(nqw, "Construction pattern definitions", roles, assets, relationships, nodes, role_links, cppredecessor, cpsequence) 

    # Output Threat Categories, Threats and Control Strategies
    output_threat_categories(nqw, "Threat category definitions")
    output_compliance_sets(nqw, "Compliance Set definitions")
    output_threats(nqw, "Threat definitions", misbehaviours, twas, roles, misbehaviour_sets, twa_sets)
    output_control_strategies(nqw, "Control Strategy definitions", controls, roles, control_sets)

    # Output default settings
    output_casettings(nqw, "CASetting definitions: whether a Control is assertible at an Asset")
    output_ma_default_levels(nqw, "MADefaultSetting definitions: default impact level for a Misbehaviour at an Asset")
    output_twaa_default_levels(nqw, "TWAADefaultSetting definitions: default TW level for a Trustworthiness Attribute at an Asset")

    # Output nodes and role links
    output_nodes(nqw, "Node definitions", nodes)
    output_role_links(nqw, "Role Link definitions", role_links)

    # Output CS, MS and TWAS
    output_sets(nqw, "Control", "Control Set definitions: combination of a Control at an asset with a given Role", control_sets)
    output_sets(nqw, "Misbehaviour", "Misbehaviour Set definitions: combination of a Misbehaviour at an asset with a given Role", misbehaviour_sets)
    output_sets(nqw, "TrustworthinessAttribute", "Trustworthiness Attribute Set definitions: combination of a Trustworthiness Attribute at an asset with a given Role", twa_sets)

# Output icon mapping file if required
if output_mapping:
    output_mapping_file(mapping_filename, nqw.g.split("/")[-1][:-1], nqw.g[1:-1])
