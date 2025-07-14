#include "modules/mesh/mesh_converter.hpp"
#include <assimp/Importer.hpp>
#include <assimp/Exporter.hpp>
#include <assimp/scene.h>
#include <assimp/postprocess.h>
#include <opencascade/OpenCascade.hxx>
#include <opencascade/BRepTools.hxx>
#include <opencascade/TopoDS.hxx>
#include <opencascade/BRep_Builder.hxx>
#include <opencascade/STEPControl.hxx>
#include <opencascade/IGESControl.hxx>
#include <bullet/btBulletDynamicsCommon.h>
#include <cgal/CGAL/Basic.h>
#include <cgal/CGAL/Polyhedron_3.h>
#include <cgal/CGAL/Surface_mesh.h>
#include <cgal/CGAL/Polygon_mesh_processing.h>
#include <draco/compression/encode.h>
#include <draco/compression/decode.h>
#include <execution>
#include <numeric>
#include <random>
#include <immintrin.h>

namespace converter::modules::mesh {

class MeshConverter::Impl {
public:
    struct MeshState {
        std::unique_ptr<Assimp::Importer> importer;
        std::unique_ptr<Assimp::Exporter> exporter;
        std::unique_ptr<btDiscreteDynamicsWorld> physics_world;
        std::unique_ptr<btBroadphaseInterface> broadphase;
        std::unique_ptr<btDefaultCollisionConfiguration> collision_config;
        std::unique_ptr<btCollisionDispatcher> dispatcher;
        std::unique_ptr<btSequentialImpulseConstraintSolver> solver;
        std::vector<std::unique_ptr<btRigidBody>> rigid_bodies;
        std::vector<std::unique_ptr<btCollisionShape>> collision_shapes;
        mutable std::shared_mutex mutex;
        MeshMetrics metrics;
        std::unordered_map<std::string, std::shared_ptr<ProcessedMesh>> mesh_cache;
    };

    std::unordered_map<std::thread::id, std::unique_ptr<MeshState>> thread_states;
    std::shared_mutex states_mutex;
    std::atomic<uint64_t> meshes_processed{0};
    std::atomic<uint64_t> vertices_processed{0};
    std::atomic<uint64_t> triangles_processed{0};
    
    MeshState& get_thread_state() {
        std::thread::id tid = std::this_thread::get_id();
        std::shared_lock lock(states_mutex);
        
        if (auto it = thread_states.find(tid); it != thread_states.end()) {
            return *it->second;
        }
        
        lock.unlock();
        std::unique_lock ulock(states_mutex);
        
        auto state = std::make_unique<MeshState>();
        state->importer = std::make_unique<Assimp::Importer>();
        state->exporter = std::make_unique<Assimp::Exporter>();
        
        initialize_physics_world(*state);
        
        auto& ref = *state;
        thread_states[tid] = std::move(state);
        return ref;
    }
    
    void initialize_physics_world(MeshState& state) {
        state.collision_config = std::make_unique<btDefaultCollisionConfiguration>();
        state.dispatcher = std::make_unique<btCollisionDispatcher>(state.collision_config.get());
        state.broadphase = std::make_unique<btDbvtBroadphase>();
        state.solver = std::make_unique<btSequentialImpulseConstraintSolver>();
        
        state.physics_world = std::make_unique<btDiscreteDynamicsWorld>(
            state.dispatcher.get(),
            state.broadphase.get(),
            state.solver.get(),
            state.collision_config.get()
        );
        
        state.physics_world->setGravity(btVector3(0, -9.81f, 0));
    }
    
    std::shared_ptr<ProcessedMesh> load_mesh(const std::string& file_path) {
        auto& state = get_thread_state();
        
        std::string cache_key = file_path + "_" + std::to_string(std::hash<std::string>{}(file_path));
        
        {
            std::shared_lock lock(state.mutex);
            if (auto it = state.mesh_cache.find(cache_key); it != state.mesh_cache.end()) {
                return it->second;
            }
        }
        
        const aiScene* scene = state.importer->ReadFile(file_path, 
            aiProcess_Triangulate |
            aiProcess_GenNormals |
            aiProcess_GenUVCoords |
            aiProcess_CalcTangentSpace |
            aiProcess_OptimizeMeshes |
            aiProcess_OptimizeGraph |
            aiProcess_JoinIdenticalVertices |
            aiProcess_ImproveCacheLocality |
            aiProcess_RemoveRedundantMaterials |
            aiProcess_FixInfacingNormals |
            aiProcess_FindDegenerates |
            aiProcess_FindInvalidData |
            aiProcess_ValidateDataStructure
        );
        
        if (!scene || scene->mFlags & AI_SCENE_FLAGS_INCOMPLETE || !scene->mRootNode) {
            throw std::runtime_error("Failed to load mesh: " + std::string(state.importer->GetErrorString()));
        }
        
        auto processed_mesh = std::make_shared<ProcessedMesh>();
        process_node(scene->mRootNode, scene, *processed_mesh);
        
        {
            std::unique_lock lock(state.mutex);
            state.mesh_cache[cache_key] = processed_mesh;
        }
        
        return processed_mesh;
    }
    
    void process_node(aiNode* node, const aiScene* scene, ProcessedMesh& mesh) {
        for (unsigned int i = 0; i < node->mNumMeshes; i++) {
            aiMesh* ai_mesh = scene->mMeshes[node->mMeshes[i]];
            auto sub_mesh = process_mesh(ai_mesh, scene);
            mesh.sub_meshes.push_back(std::move(sub_mesh));
        }
        
        for (unsigned int i = 0; i < node->mNumChildren; i++) {
            process_node(node->mChildren[i], scene, mesh);
        }
    }
    
    std::unique_ptr<SubMesh> process_mesh(aiMesh* mesh, const aiScene* scene) {
        auto sub_mesh = std::make_unique<SubMesh>();
        
        for (unsigned int i = 0; i < mesh->mNumVertices; i++) {
            Vertex vertex;
            vertex.position = {mesh->mVertices[i].x, mesh->mVertices[i].y, mesh->mVertices[i].z};
            
            if (mesh->HasNormals()) {
                vertex.normal = {mesh->mNormals[i].x, mesh->mNormals[i].y, mesh->mNormals[i].z};
            }
            
            if (mesh->mTextureCoords[0]) {
                vertex.tex_coords = {mesh->mTextureCoords[0][i].x, mesh->mTextureCoords[0][i].y};
            }
            
            if (mesh->HasTangentsAndBitangents()) {
                vertex.tangent = {mesh->mTangents[i].x, mesh->mTangents[i].y, mesh->mTangents[i].z};
                vertex.bitangent = {mesh->mBitangents[i].x, mesh->mBitangents[i].y, mesh->mBitangents[i].z};
            }
            
            if (mesh->HasVertexColors(0)) {
                vertex.color = {
                    mesh->mColors[0][i].r,
                    mesh->mColors[0][i].g,
                    mesh->mColors[0][i].b,
                    mesh->mColors[0][i].a
                };
            }
            
            sub_mesh->vertices.push_back(vertex);
        }
        
        for (unsigned int i = 0; i < mesh->mNumFaces; i++) {
            aiFace face = mesh->mFaces[i];
            for (unsigned int j = 0; j < face.mNumIndices; j++) {
                sub_mesh->indices.push_back(face.mIndices[j]);
            }
        }
        
        calculate_bounding_box(*sub_mesh);
        calculate_surface_area(*sub_mesh);
        calculate_volume(*sub_mesh);
        
        return sub_mesh;
    }
    
    void calculate_bounding_box(SubMesh& sub_mesh) {
        if (sub_mesh.vertices.empty()) return;
        
        auto min_x = std::min_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.x < b.position.x; });
        auto max_x = std::max_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.x < b.position.x; });
        
        auto min_y = std::min_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.y < b.position.y; });
        auto max_y = std::max_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.y < b.position.y; });
        
        auto min_z = std::min_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.z < b.position.z; });
        auto max_z = std::max_element(sub_mesh.vertices.begin(), sub_mesh.vertices.end(),
                                     [](const Vertex& a, const Vertex& b) { return a.position.z < b.position.z; });
        
        sub_mesh.bounding_box.min = {min_x->position.x, min_y->position.y, min_z->position.z};
        sub_mesh.bounding_box.max = {max_x->position.x, max_y->position.y, max_z->position.z};
    }
    
    void calculate_surface_area(SubMesh& sub_mesh) {
        double total_area = 0.0;
        
        for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
            if (i + 2 < sub_mesh.indices.size()) {
                const auto& v1 = sub_mesh.vertices[sub_mesh.indices[i]].position;
                const auto& v2 = sub_mesh.vertices[sub_mesh.indices[i + 1]].position;
                const auto& v3 = sub_mesh.vertices[sub_mesh.indices[i + 2]].position;
                
                Vector3 edge1 = {v2.x - v1.x, v2.y - v1.y, v2.z - v1.z};
                Vector3 edge2 = {v3.x - v1.x, v3.y - v1.y, v3.z - v1.z};
                
                Vector3 cross = {
                    edge1.y * edge2.z - edge1.z * edge2.y,
                    edge1.z * edge2.x - edge1.x * edge2.z,
                    edge1.x * edge2.y - edge1.y * edge2.x
                };
                
                double area = 0.5 * std::sqrt(cross.x * cross.x + cross.y * cross.y + cross.z * cross.z);
                total_area += area;
            }
        }
        
        sub_mesh.surface_area = total_area;
    }
    
    void calculate_volume(SubMesh& sub_mesh) {
        double volume = 0.0;
        
        for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
            if (i + 2 < sub_mesh.indices.size()) {
                const auto& v1 = sub_mesh.vertices[sub_mesh.indices[i]].position;
                const auto& v2 = sub_mesh.vertices[sub_mesh.indices[i + 1]].position;
                const auto& v3 = sub_mesh.vertices[sub_mesh.indices[i + 2]].position;
                
                volume += (v1.x * (v2.y * v3.z - v3.y * v2.z) +
                          v2.x * (v3.y * v1.z - v1.y * v3.z) +
                          v3.x * (v1.y * v2.z - v2.y * v1.z)) / 6.0;
            }
        }
        
        sub_mesh.volume = std::abs(volume);
    }
    
    std::shared_ptr<ProcessedMesh> optimize_mesh(const ProcessedMesh& mesh, const OptimizationSettings& settings) {
        auto optimized = std::make_shared<ProcessedMesh>();
        
        std::vector<std::future<std::unique_ptr<SubMesh>>> futures;
        
        for (const auto& sub_mesh : mesh.sub_meshes) {
            futures.push_back(std::async(std::launch::async, [&, sub_mesh]() {
                auto optimized_sub = std::make_unique<SubMesh>(*sub_mesh);
                
                if (settings.remove_duplicates) {
                    remove_duplicate_vertices(*optimized_sub);
                }
                
                if (settings.smooth_normals) {
                    smooth_normals(*optimized_sub);
                }
                
                if (settings.optimize_indices) {
                    optimize_vertex_cache(*optimized_sub);
                }
                
                if (settings.simplify_mesh && settings.target_reduction > 0.0) {
                    simplify_mesh(*optimized_sub, settings.target_reduction);
                }
                
                return optimized_sub;
            }));
        }
        
        for (auto& future : futures) {
            optimized->sub_meshes.push_back(future.get());
        }
        
        return optimized;
    }
    
    void remove_duplicate_vertices(SubMesh& sub_mesh) {
        std::vector<Vertex> unique_vertices;
        std::vector<uint32_t> vertex_map(sub_mesh.vertices.size());
        
        for (size_t i = 0; i < sub_mesh.vertices.size(); ++i) {
            auto it = std::find_if(unique_vertices.begin(), unique_vertices.end(),
                                  [&](const Vertex& v) {
                                      return std::abs(v.position.x - sub_mesh.vertices[i].position.x) < 1e-6 &&
                                             std::abs(v.position.y - sub_mesh.vertices[i].position.y) < 1e-6 &&
                                             std::abs(v.position.z - sub_mesh.vertices[i].position.z) < 1e-6;
                                  });
            
            if (it == unique_vertices.end()) {
                vertex_map[i] = static_cast<uint32_t>(unique_vertices.size());
                unique_vertices.push_back(sub_mesh.vertices[i]);
            } else {
                vertex_map[i] = static_cast<uint32_t>(std::distance(unique_vertices.begin(), it));
            }
        }
        
        sub_mesh.vertices = std::move(unique_vertices);
        
        for (auto& index : sub_mesh.indices) {
            index = vertex_map[index];
        }
    }
    
    void smooth_normals(SubMesh& sub_mesh) {
        std::vector<Vector3> vertex_normals(sub_mesh.vertices.size(), {0.0f, 0.0f, 0.0f});
        std::vector<int> vertex_counts(sub_mesh.vertices.size(), 0);
        
        for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
            if (i + 2 < sub_mesh.indices.size()) {
                uint32_t i1 = sub_mesh.indices[i];
                uint32_t i2 = sub_mesh.indices[i + 1];
                uint32_t i3 = sub_mesh.indices[i + 2];
                
                const auto& v1 = sub_mesh.vertices[i1].position;
                const auto& v2 = sub_mesh.vertices[i2].position;
                const auto& v3 = sub_mesh.vertices[i3].position;
                
                Vector3 edge1 = {v2.x - v1.x, v2.y - v1.y, v2.z - v1.z};
                Vector3 edge2 = {v3.x - v1.x, v3.y - v1.y, v3.z - v1.z};
                
                Vector3 normal = {
                    edge1.y * edge2.z - edge1.z * edge2.y,
                    edge1.z * edge2.x - edge1.x * edge2.z,
                    edge1.x * edge2.y - edge1.y * edge2.x
                };
                
                vertex_normals[i1].x += normal.x;
                vertex_normals[i1].y += normal.y;
                vertex_normals[i1].z += normal.z;
                vertex_counts[i1]++;
                
                vertex_normals[i2].x += normal.x;
                vertex_normals[i2].y += normal.y;
                vertex_normals[i2].z += normal.z;
                vertex_counts[i2]++;
                
                vertex_normals[i3].x += normal.x;
                vertex_normals[i3].y += normal.y;
                vertex_normals[i3].z += normal.z;
                vertex_counts[i3]++;
            }
        }
        
        for (size_t i = 0; i < sub_mesh.vertices.size(); ++i) {
            if (vertex_counts[i] > 0) {
                vertex_normals[i].x /= vertex_counts[i];
                vertex_normals[i].y /= vertex_counts[i];
                vertex_normals[i].z /= vertex_counts[i];
                
                float length = std::sqrt(vertex_normals[i].x * vertex_normals[i].x + 
                                       vertex_normals[i].y * vertex_normals[i].y + 
                                       vertex_normals[i].z * vertex_normals[i].z);
                
                if (length > 0.0f) {
                    vertex_normals[i].x /= length;
                    vertex_normals[i].y /= length;
                    vertex_normals[i].z /= length;
                }
                
                sub_mesh.vertices[i].normal = vertex_normals[i];
            }
        }
    }
    
    void optimize_vertex_cache(SubMesh& sub_mesh) {
        std::vector<uint32_t> optimized_indices;
        optimized_indices.reserve(sub_mesh.indices.size());
        
        std::vector<bool> processed(sub_mesh.vertices.size(), false);
        std::vector<uint32_t> vertex_scores(sub_mesh.vertices.size(), 0);
        
        for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
            if (i + 2 < sub_mesh.indices.size()) {
                for (int j = 0; j < 3; ++j) {
                    vertex_scores[sub_mesh.indices[i + j]]++;
                }
            }
        }
        
        auto cmp = [&](uint32_t a, uint32_t b) {
            return vertex_scores[a] > vertex_scores[b];
        };
        
        std::priority_queue<uint32_t, std::vector<uint32_t>, decltype(cmp)> vertex_queue(cmp);
        
        for (size_t i = 0; i < sub_mesh.vertices.size(); ++i) {
            if (vertex_scores[i] > 0) {
                vertex_queue.push(static_cast<uint32_t>(i));
            }
        }
        
        while (!vertex_queue.empty()) {
            uint32_t vertex_idx = vertex_queue.top();
            vertex_queue.pop();
            
            if (processed[vertex_idx]) continue;
            processed[vertex_idx] = true;
            
            for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
                if (i + 2 < sub_mesh.indices.size()) {
                    bool contains_vertex = false;
                    for (int j = 0; j < 3; ++j) {
                        if (sub_mesh.indices[i + j] == vertex_idx) {
                            contains_vertex = true;
                            break;
                        }
                    }
                    
                    if (contains_vertex) {
                        for (int j = 0; j < 3; ++j) {
                            optimized_indices.push_back(sub_mesh.indices[i + j]);
                        }
                    }
                }
            }
        }
        
        if (optimized_indices.size() == sub_mesh.indices.size()) {
            sub_mesh.indices = std::move(optimized_indices);
        }
    }
    
    void simplify_mesh(SubMesh& sub_mesh, double target_reduction) {
        size_t target_triangles = static_cast<size_t>((sub_mesh.indices.size() / 3) * (1.0 - target_reduction));
        
        struct EdgeCollapse {
            uint32_t v1, v2;
            double cost;
            Vector3 position;
        };
        
        std::vector<EdgeCollapse> edge_collapses;
        
        for (size_t i = 0; i < sub_mesh.indices.size(); i += 3) {
            if (i + 2 < sub_mesh.indices.size()) {
                for (int j = 0; j < 3; ++j) {
                    uint32_t v1 = sub_mesh.indices[i + j];
                    uint32_t v2 = sub_mesh.indices[i + (j + 1) % 3];
                    
                    if (v1 != v2) {
                        EdgeCollapse collapse;
                        collapse.v1 = std::min(v1, v2);
                        collapse.v2 = std::max(v1, v2);
                        
                        const auto& pos1 = sub_mesh.vertices[v1].position;
                        const auto& pos2 = sub_mesh.vertices[v2].position;
                        
                        collapse.position = {
                            (pos1.x + pos2.x) * 0.5f,
                            (pos1.y + pos2.y) * 0.5f,
                            (pos1.z + pos2.z) * 0.5f
                        };
                        
                        collapse.cost = std::sqrt(
                            (pos1.x - pos2.x) * (pos1.x - pos2.x) +
                            (pos1.y - pos2.y) * (pos1.y - pos2.y) +
                            (pos1.z - pos2.z) * (pos1.z - pos2.z)
                        );
                        
                        edge_collapses.push_back(collapse);
                    }
                }
            }
        }
        
        std::sort(edge_collapses.begin(), edge_collapses.end(),
                 [](const EdgeCollapse& a, const EdgeCollapse& b) {
                     return a.cost < b.cost;
                 });
        
        edge_collapses.erase(std::unique(edge_collapses.begin(), edge_collapses.end(),
                                        [](const EdgeCollapse& a, const EdgeCollapse& b) {
                                            return a.v1 == b.v1 && a.v2 == b.v2;
                                        }), edge_collapses.end());
        
        size_t current_triangles = sub_mesh.indices.size() / 3;
        size_t collapse_index = 0;
        
        while (current_triangles > target_triangles && collapse_index < edge_collapses.size()) {
            const auto& collapse = edge_collapses[collapse_index++];
            
            sub_mesh.vertices[collapse.v1].position = collapse.position;
            
            for (auto& index : sub_mesh.indices) {
                if (index == collapse.v2) {
                    index = collapse.v1;
                }
            }
            
            current_triangles--;
        }
    }
    
    std::vector<uint8_t> compress_mesh(const ProcessedMesh& mesh, CompressionType compression) {
        draco::Encoder encoder;
        
        switch (compression) {
            case CompressionType::DRACO_GEOMETRY:
                encoder.SetAttributeQuantization(draco::GeometryAttribute::POSITION, 14);
                encoder.SetAttributeQuantization(draco::GeometryAttribute::NORMAL, 10);
                encoder.SetAttributeQuantization(draco::GeometryAttribute::TEX_COORD, 12);
                break;
            case CompressionType::DRACO_LOSSLESS:
                encoder.SetAttributeQuantization(draco::GeometryAttribute::POSITION, 16);
                encoder.SetAttributeQuantization(draco::GeometryAttribute::NORMAL, 16);
                encoder.SetAttributeQuantization(draco::GeometryAttribute::TEX_COORD, 16);
                break;
            default:
                break;
        }
        
        draco::Mesh draco_mesh;
        
        for (const auto& sub_mesh : mesh.sub_meshes) {
            draco_mesh.set_num_points(sub_mesh->vertices.size());
            
            for (size_t i = 0; i < sub_mesh->indices.size(); i += 3) {
                if (i + 2 < sub_mesh->indices.size()) {
                    draco_mesh.AddFace(draco::Mesh::Face{{
                        draco::PointIndex(sub_mesh->indices[i]),
                        draco::PointIndex(sub_mesh->indices[i + 1]),
                        draco::PointIndex(sub_mesh->indices[i + 2])
                    }});
                }
            }
        }
        
        draco::EncoderBuffer buffer;
        draco::Status status = encoder.EncodeMeshToBuffer(draco_mesh, &buffer);
        
        if (!status.ok()) {
            throw std::runtime_error("Draco compression failed: " + status.error_msg());
        }
        
        return std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size());
    }
    
    std::shared_ptr<ProcessedMesh> decompress_mesh(const std::vector<uint8_t>& compressed_data) {
        draco::Decoder decoder;
        draco::DecoderBuffer buffer;
        buffer.Init(reinterpret_cast<const char*>(compressed_data.data()), compressed_data.size());
        
        auto type_status = decoder.GetEncodedGeometryType(&buffer);
        if (!type_status.ok()) {
            throw std::runtime_error("Failed to determine geometry type");
        }
        
        if (type_status.value() != draco::TRIANGULAR_MESH) {
            throw std::runtime_error("Only triangular meshes are supported");
        }
        
        auto mesh_status = decoder.DecodeMeshFromBuffer(&buffer);
        if (!mesh_status.ok()) {
            throw std::runtime_error("Draco decompression failed: " + mesh_status.status().error_msg());
        }
        
        auto draco_mesh = std::move(mesh_status).value();
        
        auto processed_mesh = std::make_shared<ProcessedMesh>();
        auto sub_mesh = std::make_unique<SubMesh>();
        
        sub_mesh->vertices.resize(draco_mesh->num_points());
        
        const draco::PointAttribute* pos_attr = draco_mesh->GetNamedAttribute(draco::GeometryAttribute::POSITION);
        const draco::PointAttribute* norm_attr = draco_mesh->GetNamedAttribute(draco::GeometryAttribute::NORMAL);
        const draco::PointAttribute* tex_attr = draco_mesh->GetNamedAttribute(draco::GeometryAttribute::TEX_COORD);
        
        for (draco::PointIndex i(0); i < draco_mesh->num_points(); ++i) {
            if (pos_attr) {
                std::array<float, 3> pos;
                pos_attr->ConvertValue<float, 3>(pos_attr->mapped_index(i), pos.data());
                sub_mesh->vertices[i.value()].position = {pos[0], pos[1], pos[2]};
            }
            
            if (norm_attr) {
                std::array<float, 3> norm;
                norm_attr->ConvertValue<float, 3>(norm_attr->mapped_index(i), norm.data());
                sub_mesh->vertices[i.value()].normal = {norm[0], norm[1], norm[2]};
            }
            
            if (tex_attr) {
                std::array<float, 2> tex;
                tex_attr->ConvertValue<float, 2>(tex_attr->mapped_index(i), tex.data());
                sub_mesh->vertices[i.value()].tex_coords = {tex[0], tex[1]};
            }
        }
        
        for (draco::FaceIndex i(0); i < draco_mesh->num_faces(); ++i) {
            const draco::Mesh::Face& face = draco_mesh->face(i);
            sub_mesh->indices.push_back(face[0].value());
            sub_mesh->indices.push_back(face[1].value());
            sub_mesh->indices.push_back(face[2].value());
        }
        
        calculate_bounding_box(*sub_mesh);
        calculate_surface_area(*sub_mesh);
        calculate_volume(*sub_mesh);
        
        processed_mesh->sub_meshes.push_back(std::move(sub_mesh));
        
        return processed_mesh;
    }
    
    void add_physics_body(const ProcessedMesh& mesh, const PhysicsProperties& properties) {
        auto& state = get_thread_state();
        
        for (const auto& sub_mesh : mesh.sub_meshes) {
            btTriangleMesh* triangle_mesh = new btTriangleMesh();
            
            for (size_t i = 0; i < sub_mesh->indices.size(); i += 3) {
                if (i + 2 < sub_mesh->indices.size()) {
                    const auto& v1 = sub_mesh->vertices[sub_mesh->indices[i]].position;
                    const auto& v2 = sub_mesh->vertices[sub_mesh->indices[i + 1]].position;
                    const auto& v3 = sub_mesh->vertices[sub_mesh->indices[i + 2]].position;
                    
                    triangle_mesh->addTriangle(
                        btVector3(v1.x, v1.y, v1.z),
                        btVector3(v2.x, v2.y, v2.z),
                        btVector3(v3.x, v3.y, v3.z)
                    );
                }
            }
            
            btCollisionShape* shape = new btBvhTriangleMeshShape(triangle_mesh, true);
            state.collision_shapes.emplace_back(shape);
            
            btTransform transform;
            transform.setIdentity();
            transform.setOrigin(btVector3(properties.position.x, properties.position.y, properties.position.z));
            
            btVector3 local_inertia(0, 0, 0);
            if (properties.mass > 0.0f) {
                shape->calculateLocalInertia(properties.mass, local_inertia);
            }
            
            btDefaultMotionState* motion_state = new btDefaultMotionState(transform);
            btRigidBody::btRigidBodyConstructionInfo rb_info(properties.mass, motion_state, shape, local_inertia);
            
            rb_info.m_restitution = properties.restitution;
            rb_info.m_friction = properties.friction;
            rb_info.m_linearDamping = properties.linear_damping;
            rb_info.m_angularDamping = properties.angular_damping;
            
            btRigidBody* body = new btRigidBody(rb_info);
            state.rigid_bodies.emplace_back(body);
            
            state.physics_world->addRigidBody(body);
        }
    }
    
    void simulate_physics(float delta_time) {
        auto& state = get_thread_state();
        state.physics_world->stepSimulation(delta_time, 10);
    }
    
    void save_mesh(const ProcessedMesh& mesh, const std::string& file_path, MeshFormat format) {
        auto& state = get_thread_state();
        
        aiScene scene;
        scene.mRootNode = new aiNode();
        scene.mNumMeshes = static_cast<unsigned int>(mesh.sub_meshes.size());
        scene.mMeshes = new aiMesh*[scene.mNumMeshes];
        
        for (size_t i = 0; i < mesh.sub_meshes.size(); ++i) {
            const auto& sub_mesh = mesh.sub_meshes[i];
            
            aiMesh* ai_mesh = new aiMesh();
            ai_mesh->mNumVertices = static_cast<unsigned int>(sub_mesh->vertices.size());
            ai_mesh->mVertices = new aiVector3D[ai_mesh->mNumVertices];
            ai_mesh->mNormals = new aiVector3D[ai_mesh->mNumVertices];
            ai_mesh->mTextureCoords[0] = new aiVector3D[ai_mesh->mNumVertices];
            ai_mesh->mNumUVComponents[0] = 2;
            
            for (size_t j = 0; j < sub_mesh->vertices.size(); ++j) {
                const auto& vertex = sub_mesh->vertices[j];
                ai_mesh->mVertices[j] = aiVector3D(vertex.position.x, vertex.position.y, vertex.position.z);
                ai_mesh->mNormals[j] = aiVector3D(vertex.normal.x, vertex.normal.y, vertex.normal.z);
                ai_mesh->mTextureCoords[0][j] = aiVector3D(vertex.tex_coords.x, vertex.tex_coords.y, 0.0f);
            }
            
            ai_mesh->mNumFaces = static_cast<unsigned int>(sub_mesh->indices.size() / 3);
            ai_mesh->mFaces = new aiFace[ai_mesh->mNumFaces];
            
            for (size_t j = 0; j < ai_mesh->mNumFaces; ++j) {
                aiFace& face = ai_mesh->mFaces[j];
                face.mNumIndices = 3;
                face.mIndices = new unsigned int[3];
                face.mIndices[0] = sub_mesh->indices[j * 3];
                face.mIndices[1] = sub_mesh->indices[j * 3 + 1];
                face.mIndices[2] = sub_mesh->indices[j * 3 + 2];
            }
            
            scene.mMeshes[i] = ai_mesh;
        }
        
        scene.mRootNode->mNumMeshes = scene.mNumMeshes;
        scene.mRootNode->mMeshes = new unsigned int[scene.mNumMeshes];
        for (unsigned int i = 0; i < scene.mNumMeshes; ++i) {
            scene.mRootNode->mMeshes[i] = i;
        }
        
        std::string format_id = [format]() {
            switch (format) {
                case MeshFormat::OBJ: return "obj";
                case MeshFormat::PLY: return "ply";
                case MeshFormat::STL: return "stl";
                case MeshFormat::GLTF: return "gltf2";
                case MeshFormat::FBX: return "fbx";
                case MeshFormat::COLLADA: return "collada";
                default: return "obj";
            }
        }();
        
        if (state.exporter->Export(&scene, format_id, file_path) != AI_SUCCESS) {
            throw std::runtime_error("Failed to export mesh: " + std::string(state.exporter->GetErrorString()));
        }
    }
    
    void update_metrics(const ProcessedMesh& mesh) {
        meshes_processed++;
        
        size_t total_vertices = 0;
        size_t total_triangles = 0;
        
        for (const auto& sub_mesh : mesh.sub_meshes) {
            total_vertices += sub_mesh->vertices.size();
            total_triangles += sub_mesh->indices.size() / 3;
        }
        
        vertices_processed += total_vertices;
        triangles_processed += total_triangles;
        
        auto& state = get_thread_state();
        std::unique_lock lock(state.mutex);
        
        state.metrics.meshes_processed = meshes_processed.load();
        state.metrics.vertices_processed = vertices_processed.load();
        state.metrics.triangles_processed = triangles_processed.load();
        state.metrics.throughput = calculate_throughput();
    }
    
    double calculate_throughput() {
        static auto start_time = std::chrono::high_resolution_clock::now();
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        if (duration.count() == 0) return 0.0;
        
        return static_cast<double>(vertices_processed.load()) / duration.count();
    }
};

MeshConverter::MeshConverter() : pimpl(std::make_unique<Impl>()) {}

MeshConverter::~MeshConverter() = default;

std::shared_ptr<ProcessedMesh> MeshConverter::load_mesh(const std::string& file_path) {
    auto mesh = pimpl->load_mesh(file_path);
    pimpl->update_metrics(*mesh);
    return mesh;
}

void MeshConverter::save_mesh(const ProcessedMesh& mesh, const std::string& file_path, MeshFormat format) {
    pimpl->save_mesh(mesh, file_path, format);
}

std::shared_ptr<ProcessedMesh> MeshConverter::optimize_mesh(const ProcessedMesh& mesh, const OptimizationSettings& settings) {
    auto optimized = pimpl->optimize_mesh(mesh, settings);
    pimpl->update_metrics(*optimized);
    return optimized;
}

std::vector<uint8_t> MeshConverter::compress_mesh(const ProcessedMesh& mesh, CompressionType compression) {
    return pimpl->compress_mesh(mesh, compression);
}

std::shared_ptr<ProcessedMesh> MeshConverter::decompress_mesh(const std::vector<uint8_t>& compressed_data) {
    auto mesh = pimpl->decompress_mesh(compressed_data);
    pimpl->update_metrics(*mesh);
    return mesh;
}

void MeshConverter::add_physics_body(const ProcessedMesh& mesh, const PhysicsProperties& properties) {
    pimpl->add_physics_body(mesh, properties);
}

void MeshConverter::simulate_physics(float delta_time) {
    pimpl->simulate_physics(delta_time);
}

MeshMetrics MeshConverter::get_metrics() const {
    auto& state = pimpl->get_thread_state();
    std::shared_lock lock(state.mutex);
    return state.metrics;
}

} 